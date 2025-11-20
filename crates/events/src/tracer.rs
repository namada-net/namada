//! Trace the origin of emitted events.
//!
//! ## Example
//!
//! ```
//! #[track_caller]
//! fn emit_event(event: crate::Event, events: &mut impl EmitEvents) {
//!     let mut tracer = EventTracer::trace(events);
//!     tracer.emit(event);
//! }
//! ```

use std::borrow::Cow;
use std::fmt;
use std::mem::{self, MaybeUninit};
use std::ops::DerefMut;
use std::panic::Location;
use std::str::FromStr;

use namada_core::booleans::BoolResultUnitExt;

use super::{EmitEvents, EventToEmit};
use crate::extend::{ComposeEvent, EventAttributeEntry};

/// The origin of an event in source code.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EventTrace<'a> {
    pkg_name: Cow<'a, str>,
    pkg_version: Cow<'a, str>,
    file: Cow<'a, str>,
    line: u32,
    column: u32,
}

impl FromStr for EventTrace<'_> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bindings = s.split(',').map(|binding| {
            binding.split_once('=').ok_or_else(|| {
                format!("Invalid event trace binding: {binding}")
            })
        });

        mod bits {
            pub const DONE: i32 = PKG_NAME | PKG_VERSION | FILE | LINE | COLUMN;

            pub const PKG_NAME: i32 = 0b1;
            pub const PKG_VERSION: i32 = 0b10;
            pub const FILE: i32 = 0b100;
            pub const LINE: i32 = 0b1000;
            pub const COLUMN: i32 = 0b10000;
        }

        macro_rules! init_trace_field {
            ($trace:expr => $field:ident : $type:ty = $value:expr) => {
                $trace
                    .as_mut_ptr()
                    .cast::<u8>()
                    .wrapping_add(mem::offset_of!(Self, $field))
                    .cast::<$type>()
                    .write($value);
            };
        }

        let mut init_state = 0i32;
        let mut trace: MaybeUninit<EventTrace<'static>> = MaybeUninit::uninit();

        for maybe_binding in bindings {
            let (field, value) = maybe_binding?;

            match field {
                "pkg_name" => {
                    unsafe {
                        init_trace_field!(trace => pkg_name: Cow<'static, str> = Cow::Owned(value.to_owned()));
                    }

                    init_state |= bits::PKG_NAME;
                }
                "pkg_version" => {
                    unsafe {
                        init_trace_field!(trace => pkg_version: Cow<'static, str> = Cow::Owned(value.to_owned()));
                    }

                    init_state |= bits::PKG_VERSION;
                }
                "file" => {
                    unsafe {
                        init_trace_field!(trace => file: Cow<'static, str> = Cow::Owned(value.to_owned()));
                    }

                    init_state |= bits::FILE;
                }
                "line" => {
                    let line = value.parse().map_err(|err| {
                        format!(
                            "Failed to parse event trace file line: {value}: \
                             {err}"
                        )
                    })?;
                    unsafe {
                        init_trace_field!(trace => line: u32 = line);
                    }

                    init_state |= bits::LINE;
                }
                "column" => {
                    let column = value.parse().map_err(|err| {
                        format!(
                            "Failed to parse event trace file column: \
                             {value}: {err}"
                        )
                    })?;
                    unsafe {
                        init_trace_field!(trace => column: u32 = column);
                    }

                    init_state |= bits::COLUMN;
                }
                _ => return Err(format!("Unknown event trace field: {field}")),
            }
        }

        (init_state == bits::DONE).ext_ok_or_else(|| {
            "Some fields were not initialized in the event trace".to_owned()
        })?;

        Ok(unsafe { trace.assume_init() })
    }
}

impl fmt::Display for EventTrace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            pkg_name,
            pkg_version,
            file,
            line,
            column,
        } = self;
        write!(
            f,
            "pkg_name={pkg_name},pkg_version={pkg_version},file={file},\
             line={line},column={column}"
        )
    }
}

/// Tracer of emitted events.
pub struct EventTracer<W> {
    wrapped: W,
    pkg_name: &'static str,
    pkg_version: &'static str,
}

impl<W> EventTracer<W> {
    /// Build a new [`EventTracer`].
    pub const fn trace(wrapped: W) -> Self {
        Self {
            wrapped,
            pkg_name: env!("CARGO_PKG_NAME"),
            pkg_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

impl<EE, W> EmitEvents for EventTracer<W>
where
    EE: EmitEvents,
    W: DerefMut<Target = EE>,
{
    #[track_caller]
    fn emit<E>(&mut self, event: E)
    where
        E: EventToEmit,
    {
        let caller = Location::caller();

        self.wrapped.emit(event.with(EventOrigin(EventTrace {
            pkg_name: Cow::Borrowed(self.pkg_name),
            pkg_version: Cow::Borrowed(self.pkg_version),
            file: Cow::Borrowed(caller.file()),
            line: caller.line(),
            column: caller.column(),
        })));
    }

    #[track_caller]
    fn emit_many<B, E>(&mut self, event_batch: B)
    where
        B: IntoIterator<Item = E>,
        E: EventToEmit,
    {
        let caller = Location::caller();

        self.wrapped.emit_many(event_batch.into_iter().map(|event| {
            event.with(EventOrigin(EventTrace {
                pkg_name: Cow::Borrowed(self.pkg_name),
                pkg_version: Cow::Borrowed(self.pkg_version),
                file: Cow::Borrowed(caller.file()),
                line: caller.line(),
                column: caller.column(),
            }))
        }));
    }
}

/// Extend an [`Event`](super::Event) with data pertaining to its origin in
/// source code.
pub struct EventOrigin<'a>(pub EventTrace<'a>);

impl<'a> EventAttributeEntry<'a> for EventOrigin<'a> {
    type Value = EventTrace<'a>;
    type ValueOwned = EventTrace<'static>;

    const KEY: &'static str = "event-origin";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, EventLevel, EventTypeBuilder};

    const fn dummy_trace() -> EventTrace<'static> {
        EventTrace {
            pkg_name: Cow::Borrowed("pkg"),
            pkg_version: Cow::Borrowed("ver"),
            file: Cow::Borrowed("src/file.rs"),
            line: 1,
            column: 2,
        }
    }

    #[test]
    fn test_event_trace_emit_event() {
        let (event, start_line, end_line) = {
            let ev = Event::new(
                EventTypeBuilder::new_with_type("test").build(),
                EventLevel::Tx,
            );
            let mut events = Vec::with_capacity(1);

            const START_LINE: u32 = line!();
            emit_event(ev, &mut events);
            const END_LINE: u32 = line!();

            (events.pop().unwrap(), START_LINE, END_LINE)
        };

        let trace = event.read_attribute::<EventOrigin<'_>>().unwrap();

        assert!(trace.line > start_line && trace.line < end_line);
        assert_eq!(trace.file, file!());
        assert_eq!(trace.pkg_name, env!("CARGO_PKG_NAME"));
        assert_eq!(trace.pkg_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_event_trace_roundtrip() {
        let serialized = dummy_trace().to_string();
        let deserialized: EventTrace<'static> = serialized.parse().unwrap();

        assert_eq!(deserialized, dummy_trace());
    }

    #[test]
    fn test_event_trace_fields_missing() {
        let serialized = "pkg_name=pkg,pkg_version=ver";
        let result: Result<EventTrace<'static>, _> = serialized.parse();

        assert_eq!(
            result,
            Err("Some fields were not initialized in the event trace"
                .to_owned())
        );
    }

    #[test]
    fn test_event_trace_invalid_line() {
        let serialized = "pkg_name=pkg,line=bruv";
        let result: Result<EventTrace<'static>, _> = serialized.parse();

        assert_eq!(
            result,
            Err(
                "Failed to parse event trace file line: bruv: invalid digit \
                 found in string"
                    .to_owned()
            )
        );
    }

    #[track_caller]
    fn emit_event(event: Event, events: &mut impl EmitEvents) {
        let mut tracer = EventTracer::trace(events);
        tracer.emit(event);
    }
}
