use crate::ringbuffer::PacketData;

/// Renders a beautiful, ANSI-colorized hexdump of PacketData to standard output.
/// High-end visual aesthetics:
/// - Dim Gray (\x1B[90m) for null bytes (0x00).
/// - Cyan (\x1B[36m) for readable ASCII graphics/spaces.
/// - Green (\x1B[32m) for other control and raw characters.
pub fn hexdump(data: &PacketData<'_>, max_dump: usize) {
    let (part1, part2) = match data {
        PacketData::Contiguous(s) => (*s, &[] as &[u8]),
        PacketData::Wrapped { part1, part2 } => (*part1, *part2),
    };

    let mut i = 0;
    let mut chars = String::new();

    for chunk in [part1, part2].iter() {
        for &byte in chunk.iter() {
            if i % 16 == 0 {
                if i > 0 {
                    println!("  \x1B[32m{}\x1B[0m", chars);
                    chars.clear();
                }
                print!("    \x1B[90m{:04x}:\x1B[0m ", i);
            }

            // Print byte in hex (colorized depending on value type)
            if byte.is_ascii_graphic() {
                print!("\x1B[36m{:02x}\x1B[0m ", byte);
            } else if byte == 0x0D || byte == 0x0A {
                print!("\x1B[32m{:02x}\x1B[0m ", byte); // CR/LF green
            } else if byte == 0 {
                print!("\x1B[90m{:02x}\x1B[0m ", byte); // Null-byte gray
            } else {
                print!("{:02x} ", byte);
            }

            // Collect ASCII representation
            if byte.is_ascii_graphic() || byte == b' ' {
                chars.push(byte as char);
            } else if byte == 0x0D || byte == 0x0A {
                chars.push('↵');
            } else {
                chars.push('.');
            }

            i += 1;
            if i >= max_dump {
                break;
            }
        }
        if i >= max_dump {
            break;
        }
    }

    // Pad the last line and print the remaining chars
    if i % 16 != 0 {
        let padding = 16 - (i % 16);
        for _ in 0..padding {
            print!("   ");
        }
        println!("  \x1B[32m{}\x1B[0m", chars);
    } else if i > 0 {
        println!("  \x1B[32m{}\x1B[0m", chars);
    }

    if data.len() > max_dump {
        println!("    \x1B[90m... (truncated {} bytes)\x1B[0m", data.len() - max_dump);
    }
}
