use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::mpsc::{self, Receiver, SyncSender},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    thread::{self, JoinHandle},
};

use vmm_sys_util::eventfd::EventFd;

use crate::{Result, UhvmError};
use crate::{SeccompLevel, seccomp};

/// UART input channel sender.
pub struct SerialInput {
    sender: SyncSender<u8>,
    irq: EventFd,
    receive_interrupt_enabled: Arc<AtomicBool>,
    irq_causes: Arc<AtomicU8>,
}

impl SerialInput {
    /// Sends a byte to the UART and wakes the guest when receive interrupts are enabled.
    pub fn send(&self, byte: u8) -> std::result::Result<(), mpsc::SendError<u8>> {
        self.sender.send(byte)?;
        if self.receive_interrupt_enabled.load(Ordering::Acquire)
            && self.irq_causes.fetch_or(1, Ordering::AcqRel) & 1 == 0
        {
            let _ = self.irq.write(1);
        }
        Ok(())
    }
}

/// Minimal 16550A serial device.
pub struct SerialPort {
    registers: [u8; 8],
    divisor: [u8; 2],
    fifo_control: u8,
    input: Receiver<u8>,
    pending_input: VecDeque<u8>,
    output: Option<SyncSender<u8>>,
    irq: EventFd,
    thre_pending: bool,
    receive_interrupt_enabled: Arc<AtomicBool>,
    irq_causes: Arc<AtomicU8>,
}

impl SerialPort {
    /// Creates a UART and its stdin input channel.
    pub fn new(output: SyncSender<u8>, irq: EventFd) -> Result<(Self, SerialInput)> {
        let (sender, receiver) = mpsc::sync_channel(16);
        let input_irq = irq
            .try_clone()
            .map_err(|error| UhvmError::new(format!("clone serial input irq eventfd: {error}")))?;
        let receive_interrupt_enabled = Arc::new(AtomicBool::new(false));
        let irq_causes = Arc::new(AtomicU8::new(0));
        Ok((
            Self {
                registers: [0; 8],
                divisor: [1, 0],
                fifo_control: 0,
                input: receiver,
                pending_input: VecDeque::new(),
                output: Some(output),
                irq,
                thre_pending: true,
                receive_interrupt_enabled: Arc::clone(&receive_interrupt_enabled),
                irq_causes: Arc::clone(&irq_causes),
            },
            SerialInput {
                sender,
                irq: input_irq,
                receive_interrupt_enabled,
                irq_causes,
            },
        ))
    }

    /// Reads an 8-bit UART register.
    pub fn read(&mut self, port: u16) -> u8 {
        self.collect_input();
        let Some(offset) = port.checked_sub(0x3f8).map(usize::from) else {
            return 0;
        };
        if offset >= self.registers.len() {
            return 0;
        }
        if self.registers[3] & 0x80 != 0 {
            match offset {
                0 => return self.divisor[0],
                1 => return self.divisor[1],
                _ => {}
            }
        }
        match offset {
            0 => {
                let byte = self.pending_input.pop_front().unwrap_or(0);
                self.update_irq();
                byte
            }
            1 => self.registers[1],
            2 => {
                let identification = self.interrupt_identification();
                if identification == 0x02 {
                    self.thre_pending = false;
                }
                self.update_irq();
                identification | if self.fifo_control & 1 != 0 { 0xc0 } else { 0 }
            }
            3 => self.registers[3],
            4 => self.registers[4],
            5 => 0x60 | u8::from(!self.pending_input.is_empty()),
            6 => self.modem_status(),
            7 => self.registers[7],
            _ => 0,
        }
    }

    /// Writes an 8-bit UART register.
    pub fn write(&mut self, port: u16, value: u8) -> Result<()> {
        let Some(offset) = port.checked_sub(0x3f8).map(usize::from) else {
            return Ok(());
        };
        if offset >= self.registers.len() {
            return Ok(());
        }
        if self.registers[3] & 0x80 != 0 {
            match offset {
                0 => {
                    self.divisor[0] = value;
                    return Ok(());
                }
                1 => {
                    self.divisor[1] = value;
                    return Ok(());
                }
                _ => {}
            }
        }
        match offset {
            0 => {
                if self.registers[4] & 0x10 != 0 {
                    self.pending_input.push_back(value);
                } else {
                    self.output
                        .as_ref()
                        .ok_or_else(|| UhvmError::new("serial output channel is closed"))?
                        .send(value)
                        .map_err(|_| UhvmError::new("serial output thread has exited"))?;
                }
                self.thre_pending = true;
                self.update_irq();
            }
            1 => {
                let previously_enabled = self.registers[1] & 0x02 != 0;
                self.registers[1] = value & 0x0f;
                self.receive_interrupt_enabled
                    .store(self.registers[1] & 0x01 != 0, Ordering::Release);
                if !previously_enabled && self.registers[1] & 0x02 != 0 {
                    self.thre_pending = true;
                }
                self.collect_input();
            }
            2 => {
                self.fifo_control = value & 1;
                if value & 0x02 != 0 {
                    self.pending_input.clear();
                }
                if value & 0x04 != 0 {
                    self.thre_pending = true;
                }
                self.update_irq();
            }
            3 => self.registers[3] = value,
            4 => self.registers[4] = value,
            7 => self.registers[7] = value,
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn close_output(&mut self) {
        self.output.take();
    }

    fn collect_input(&mut self) {
        while self.pending_input.len() < 16 {
            let Ok(byte) = self.input.try_recv() else {
                break;
            };
            self.pending_input.push_back(byte);
        }
        self.update_irq();
    }

    fn interrupt_identification(&self) -> u8 {
        if self.registers[1] & 0x01 != 0 && !self.pending_input.is_empty() {
            0x04
        } else if self.registers[1] & 0x02 != 0 && self.thre_pending {
            0x02
        } else {
            0x01
        }
    }

    fn modem_status(&self) -> u8 {
        let modem_control = self.registers[4];
        if modem_control & 0x10 == 0 {
            return 0xb0;
        }
        let mut status = 0;
        if modem_control & 0x01 != 0 {
            status |= 0x20;
        }
        if modem_control & 0x02 != 0 {
            status |= 0x10;
        }
        if modem_control & 0x04 != 0 {
            status |= 0x40;
        }
        if modem_control & 0x08 != 0 {
            status |= 0x80;
        }
        status
    }

    fn update_irq(&mut self) {
        let mut causes = 0;
        if self.registers[1] & 0x01 != 0 && !self.pending_input.is_empty() {
            causes |= 1;
        }
        if self.registers[1] & 0x02 != 0 && self.thre_pending {
            causes |= 2;
        }
        let previous_causes = self.irq_causes.swap(causes, Ordering::AcqRel);
        if causes & !previous_causes != 0 {
            let _ = self.irq.write(1);
        }
    }
}

pub(crate) fn spawn_output_writer(
    mut output: Box<dyn Write + Send>,
    seccomp_level: SeccompLevel,
) -> io::Result<(SyncSender<u8>, JoinHandle<Result<()>>)> {
    let (sender, receiver) = mpsc::sync_channel(65_536);
    let thread = thread::Builder::new()
        .name(String::from("uhvm-serial-out"))
        .spawn(move || {
            seccomp::apply_vmm_filter(seccomp_level)?;
            let mut buffer = Vec::new();
            while let Ok(first) = receiver.recv() {
                buffer.clear();
                buffer.push(first);
                while let Ok(byte) = receiver.try_recv() {
                    buffer.push(byte);
                }
                output
                    .write_all(&buffer)
                    .map_err(|error| UhvmError::new(format!("write serial output: {error}")))?;
                output
                    .flush()
                    .map_err(|error| UhvmError::new(format!("flush serial output: {error}")))?;
            }
            Ok(())
        })?;
    Ok((sender, thread))
}

/// Starts a stdin reader feeding the serial channel.
pub fn spawn_stdin_reader(
    input: SerialInput,
    seccomp_level: SeccompLevel,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(String::from("uhvm-serial-input"))
        .spawn(move || {
            if seccomp::apply_vmm_filter(seccomp_level).is_err() {
                return;
            }
            let stdin = io::stdin();
            let mut input_reader = stdin.lock();
            let mut bytes = [0_u8; 256];
            loop {
                match input_reader.read(&mut bytes) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        for byte in &bytes[..count] {
                            if input.send(*byte).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::mpsc::{self, Receiver};

    use vmm_sys_util::eventfd::EventFd;

    use super::{SerialInput, SerialPort};

    fn new_test_serial(
        irq: EventFd,
    ) -> Result<(SerialPort, SerialInput, Receiver<u8>), Box<dyn Error>> {
        let (output, output_receiver) = mpsc::sync_channel(65_536);
        let (serial, input) = SerialPort::new(output, irq)?;
        Ok((serial, input, output_receiver))
    }

    #[test]
    fn uart_dlab_controls_divisor_registers() -> Result<(), Box<dyn Error>> {
        let (mut serial, _, _output) = new_test_serial(EventFd::new(0)?)?;
        serial.write(0x3fb, 0x80)?;
        serial.write(0x3f8, 7)?;
        serial.write(0x3f9, 2)?;
        assert_eq!(serial.read(0x3f8), 7);
        assert_eq!(serial.read(0x3f9), 2);
        serial.write(0x3fb, 0)?;
        assert_eq!(serial.read(0x3f8), 0);
        Ok(())
    }

    #[test]
    fn uart_reports_lsr_and_thre_interrupt() -> Result<(), Box<dyn Error>> {
        let irq = EventFd::new(0)?;
        let irq_probe = irq.try_clone()?;
        let (mut serial, input, _output) = new_test_serial(irq)?;
        serial.write(0x3f9, 0x03)?;
        assert_eq!(serial.read(0x3fd), 0x60);
        assert_eq!(serial.read(0x3fa), 0x02);
        assert_eq!(serial.read(0x3fa), 0x01);
        assert_eq!(irq_probe.read()?, 1);
        input.send(b'x')?;
        assert_eq!(irq_probe.read()?, 1);
        assert_eq!(serial.read(0x3fd), 0x61);
        assert_eq!(serial.read(0x3fa), 0x04);
        assert_eq!(serial.read(0x3f8), b'x');
        Ok(())
    }

    #[test]
    fn uart_msr_maps_modem_control_in_loopback() -> Result<(), Box<dyn Error>> {
        let (mut serial, _, _output) = new_test_serial(EventFd::new(0)?)?;
        serial.write(0x3fb, 0x80)?;
        serial.write(0x3fc, 0x1a)?;
        assert_eq!(serial.read(0x3fe), 0x90);
        serial.write(0x3fa, 0x01)?;
        assert_eq!(serial.read(0x3fa), 0xc1);
        serial.write(0x3fc, 0x1f)?;
        assert_eq!(serial.read(0x3fe), 0xf0);
        serial.write(0x3fb, 0)?;
        serial.write(0x3fc, 0)?;
        assert_eq!(serial.read(0x3fe), 0xb0);
        Ok(())
    }

    #[test]
    fn uart_iir_reports_fifo_enabled_bits() -> Result<(), Box<dyn Error>> {
        let (mut serial, _, _output) = new_test_serial(EventFd::new(0)?)?;
        assert_eq!(serial.read(0x3fa), 0x01);
        serial.write(0x3fa, 0x01)?;
        assert_eq!(serial.read(0x3fa), 0xc1);
        Ok(())
    }

    #[test]
    fn uart_fifo_transmitter_reset_reasserts_thre() -> Result<(), Box<dyn Error>> {
        let (mut serial, _, _output) = new_test_serial(EventFd::new(0)?)?;
        serial.write(0x3f9, 0x02)?;
        assert_eq!(serial.read(0x3fa), 0x02);
        assert_eq!(serial.read(0x3fa), 0x01);
        serial.write(0x3fa, 0x05)?;
        assert_eq!(serial.read(0x3fa), 0xc2);
        Ok(())
    }

    #[test]
    fn queued_input_interrupts_when_receive_interrupts_are_enabled() -> Result<(), Box<dyn Error>> {
        let irq = EventFd::new(0)?;
        let irq_probe = irq.try_clone()?;
        let (mut serial, input, _output) = new_test_serial(irq)?;
        input.send(b'x')?;
        serial.write(0x3f9, 0x01)?;
        assert_eq!(irq_probe.read()?, 1);
        assert_eq!(serial.read(0x3fd), 0x61);
        assert_eq!(serial.read(0x3fa), 0x04);
        assert_eq!(serial.read(0x3f8), b'x');
        Ok(())
    }
}
