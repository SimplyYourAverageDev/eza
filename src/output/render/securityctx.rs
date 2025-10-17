// SPDX-FileCopyrightText: 2024 Christina Sørensen
// SPDX-License-Identifier: EUPL-1.2
//
// SPDX-FileCopyrightText: 2023-2024 Christina Sørensen, eza contributors
// SPDX-FileCopyrightText: 2014 Benjamin Sago
// SPDX-License-Identifier: MIT
use nu_ansi_term::Style;
#[cfg(windows)]
use unicode_width::UnicodeWidthStr;

use crate::fs::fields as f;
use crate::output::cell::{DisplayWidth, TextCell};

impl f::SecurityContext<'_> {
    pub fn render<C: Colours>(&self, colours: &C) -> TextCell {
        match &self.context {
            f::SecurityContextType::None => TextCell::paint_str(colours.none(), "?"),
            f::SecurityContextType::SELinux(context) => {
                let mut chars = Vec::with_capacity(7);

                for (i, part) in context.split(':').enumerate() {
                    let partcolour = match i {
                        0 => colours.selinux_user(),
                        1 => colours.selinux_role(),
                        2 => colours.selinux_type(),
                        _ => colours.selinux_range(),
                    };
                    if i > 0 {
                        chars.push(colours.selinux_colon().paint(":"));
                    }
                    chars.push(partcolour.paint(String::from(part)));
                }

                TextCell {
                    contents: chars.into(),
                    width: DisplayWidth::from(context.len()),
                }
            }
            #[cfg(windows)]
            f::SecurityContextType::Windows(info) => {
                let mut contents = Vec::with_capacity(3);
                let mut width = UnicodeWidthStr::width(info.owner.as_str());
                contents.push(colours.selinux_user().paint(info.owner.clone()));

                if let Some(group) = &info.group {
                    let separator = " / ";
                    width += UnicodeWidthStr::width(separator);
                    contents.push(colours.selinux_colon().paint(separator.to_string()));

                    width += UnicodeWidthStr::width(group.as_str());
                    contents.push(colours.selinux_role().paint(group.clone()));
                }

                TextCell {
                    contents: contents.into(),
                    width: DisplayWidth::from(width),
                }
            }
        }
    }
}

#[rustfmt::skip]
pub trait Colours {
    fn none(&self) -> Style;
    fn selinux_colon(&self) -> Style;
    fn selinux_user(&self)  -> Style;
    fn selinux_role(&self)  -> Style;
    fn selinux_type(&self)  -> Style;
    fn selinux_range(&self) -> Style;
}
