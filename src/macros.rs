// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#[macro_export]
macro_rules! cli_println {
    ($text:literal) => {{
        cli_println!(White, $text);
    }};
    ($colour:ident, $text:literal) => {{
        cli_println!($colour, $text, );
    }};
    ($colour:ident, $text:literal, $($args:tt)*) => {{
        let mut skin = termimad::MadSkin::default();
        use termimad::crossterm::style::Color::*;
        skin.bold.set_fg($colour);
        skin.print_inline(format!(concat!($text, "\n"), $($args)*).as_str());
    }};
}
