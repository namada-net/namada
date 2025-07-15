//! Extend [events](Event) with additional fields.

use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::str::FromStr;

use namada_core::address::Address;
use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use serde::Deserializer;

use super::*;

/// Map of event attributes.
pub trait AttributesMap {
    /// Insert a new attribute.
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>;

    /// Delete an attribute.
    fn delete_attribute(&mut self, key: &str);

    /// Retrieve an attribute.
    fn retrieve_attribute(&self, key: &str) -> Option<&str>;

    /// Check for the existence of an attribute.
    fn is_attribute(&self, key: &str) -> bool;

    /// Iterate over all the key value pairs.
    fn iter_attributes(&self) -> impl Iterator<Item = (&str, &str)>;
}

impl AttributesMap for HashMap<String, String> {
    #[inline]
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.insert(key.into(), value.into());
    }

    #[inline]
    fn delete_attribute(&mut self, key: &str) {
        self.swap_remove(key);
    }

    #[inline]
    fn retrieve_attribute(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_ref)
    }

    #[inline]
    fn is_attribute(&self, key: &str) -> bool {
        self.contains_key(key)
    }

    #[inline]
    fn iter_attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl AttributesMap for BTreeMap<String, String> {
    #[inline]
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.insert(key.into(), value.into());
    }

    #[inline]
    fn delete_attribute(&mut self, key: &str) {
        self.remove(key);
    }

    #[inline]
    fn retrieve_attribute(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_ref)
    }

    #[inline]
    fn is_attribute(&self, key: &str) -> bool {
        self.contains_key(key)
    }

    #[inline]
    fn iter_attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl AttributesMap for Vec<namada_core::tendermint::abci::EventAttribute> {
    #[inline]
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.push((key, value, true).into());
    }

    #[inline]
    fn delete_attribute(&mut self, key: &str) {
        self.retain(|attr| match attr.key_str() {
            Ok(k) => k != key,
            Err(e) => {
                tracing::debug!("Attribute key is malformed UTF-8: {e}");
                true
            }
        })
    }

    #[inline]
    fn retrieve_attribute(&self, key: &str) -> Option<&str> {
        self.iter().find_map(|attr| match attr.key_str() {
            Ok(k) if k == key => match attr.value_str() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::debug!("Attribute value is malformed UTF-8: {e}");
                    None
                }
            },
            Ok(_) => None,
            Err(e) => {
                tracing::debug!("Attribute key is malformed UTF-8: {e}");
                None
            }
        })
    }

    #[inline]
    fn is_attribute(&self, key: &str) -> bool {
        self.iter().any(|attr| match attr.key_str() {
            Ok(k) => k == key,
            Err(e) => {
                tracing::debug!("Attribute key is malformed UTF-8: {e}");
                false
            }
        })
    }

    #[inline]
    fn iter_attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.iter().filter_map(|attr| {
            match (attr.key_str(), attr.value_str()) {
                (Ok(k), Ok(v)) => Some((k, v)),
                _ => {
                    tracing::debug!(
                        "Attribute key or value is malformed UTF-8",
                    );
                    None
                }
            }
        })
    }
}

impl AttributesMap
    for Vec<namada_core::tendermint_proto::abci::EventAttribute>
{
    #[inline]
    fn insert_attribute<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.push(namada_core::tendermint_proto::abci::EventAttribute {
            key: key.into(),
            value: value.into(),
            index: true,
        });
    }

    #[inline]
    fn delete_attribute(&mut self, key: &str) {
        self.retain(|attr| attr.key != key);
    }

    #[inline]
    fn retrieve_attribute(&self, key: &str) -> Option<&str> {
        self.iter().find_map(|attr| {
            if attr.key == key {
                Some(attr.value.as_str())
            } else {
                None
            }
        })
    }

    #[inline]
    fn is_attribute(&self, key: &str) -> bool {
        self.iter().any(|attr| attr.key == key)
    }

    #[inline]
    fn iter_attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.iter()
            .map(|attr| (attr.key.as_str(), attr.value.as_str()))
    }
}

/// Provides event composition routines.
pub trait ComposeEvent {
    /// Compose an [event](Event) with new data.
    fn with<NEW>(self, data: NEW) -> CompositeEvent<NEW, Self>
    where
        Self: Sized;
}

impl<E> ComposeEvent for E
where
    E: Into<Event>,
{
    #[inline(always)]
    fn with<NEW>(self, data: NEW) -> CompositeEvent<NEW, E> {
        CompositeEvent::new(self, data)
    }
}

/// Event composed of various other event extensions.
#[derive(Clone, Debug)]
pub struct CompositeEvent<DATA, E> {
    base_event: E,
    data: DATA,
}

impl<E, DATA> CompositeEvent<DATA, E> {
    /// Create a new composed event.
    pub const fn new(base_event: E, data: DATA) -> Self {
        Self { base_event, data }
    }
}

impl<E, DATA> From<CompositeEvent<DATA, E>> for Event
where
    E: Into<Event>,
    DATA: ExtendEvent,
{
    #[inline]
    fn from(composite: CompositeEvent<DATA, E>) -> Event {
        let CompositeEvent { base_event, data } = composite;

        let mut base_event = base_event.into();
        data.extend_event(&mut base_event);

        base_event
    }
}

impl<E, DATA> EventToEmit for CompositeEvent<DATA, E>
where
    E: EventToEmit,
    DATA: ExtendEvent,
{
    const DOMAIN: &'static str = E::DOMAIN;
}

/// Extend an [`AttributesMap`] implementation with the ability
/// to add new attributes from domain types.
pub trait ExtendAttributesMap: Sized {
    /// Insert a new attribute into a map of event attributes.
    fn with_attribute<DATA>(&mut self, data: DATA) -> &mut Self
    where
        DATA: ExtendEventAttributes;
}

impl<A: AttributesMap> ExtendAttributesMap for A {
    #[inline(always)]
    fn with_attribute<DATA>(&mut self, data: DATA) -> &mut Self
    where
        DATA: ExtendEventAttributes,
    {
        data.extend_event_attributes(self);
        self
    }
}

/// Represents an entry in the attributes of an [`Event`].
pub trait EventAttributeEntry<'a> {
    /// Key to read or write and event attribute to.
    const KEY: &'static str;

    /// Data to be stored in the given `KEY`.
    type Value;

    /// Identical to [`Self::Value`], with the exception that this
    /// should be an owned variant of that type.
    type ValueOwned;

    /// Return the data to be stored in the given `KEY`.
    fn into_value(self) -> Self::Value;
}

/// Extend an [event](Event) with additional attributes.
pub trait ExtendEventAttributes {
    /// Add additional attributes to some `event`.
    fn extend_event_attributes<A>(self, attributes: &mut A)
    where
        A: AttributesMap;
}

impl<'value, DATA> ExtendEventAttributes for DATA
where
    DATA: EventAttributeEntry<'value>,
    DATA::Value: ToString,
{
    #[inline]
    fn extend_event_attributes<A>(self, attributes: &mut A)
    where
        A: AttributesMap,
    {
        attributes.insert_attribute(
            DATA::KEY.to_string(),
            self.into_value().to_string(),
        );
    }
}

/// Read an attribute from an [event](Event)'s attributes.
pub trait ReadFromEventAttributes<'value> {
    /// The attribute to be read.
    type Value;

    /// Read an attribute from the provided event attributes.
    fn read_opt_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<Option<Self::Value>, EventError>
    where
        A: AttributesMap;

    /// Read an attribute from the provided event attributes.
    fn read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<Self::Value, EventError>
    where
        A: AttributesMap;
}

// NB: some domain specific types take references instead of owned
// values as arguments, so we must decode into the owned counterparts
// of these types... hence the trait spaghetti
impl<'value, DATA> ReadFromEventAttributes<'value> for DATA
where
    DATA: EventAttributeEntry<'value>,
    <DATA as EventAttributeEntry<'value>>::ValueOwned: FromStr,
    <<DATA as EventAttributeEntry<'value>>::ValueOwned as FromStr>::Err:
        Display,
{
    type Value = <DATA as EventAttributeEntry<'value>>::ValueOwned;

    #[inline]
    fn read_opt_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<Option<Self::Value>, EventError>
    where
        A: AttributesMap,
    {
        attributes
            .retrieve_attribute(DATA::KEY)
            .map(|encoded_value| {
                encoded_value.parse().map_err(
                    |err: <Self::Value as FromStr>::Err| {
                        EventError::AttributeEncoding(err.to_string())
                    },
                )
            })
            .transpose()
    }

    #[inline]
    fn read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<Self::Value, EventError>
    where
        A: AttributesMap,
    {
        Self::read_opt_from_event_attributes(attributes)?.ok_or(
            EventError::MissingAttribute(
                <Self as EventAttributeEntry<'value>>::KEY,
            ),
        )
    }
}

/// Read a raw (string encoded) attribute from an [event](Event)'s attributes.
pub trait RawReadFromEventAttributes<'value> {
    /// Check if the associated attribute is present in the provided event
    /// attributes.
    fn check_if_present_in<A>(attributes: &A) -> bool
    where
        A: AttributesMap;

    /// Read a string encoded attribute from the provided event attributes.
    fn raw_read_opt_from_event_attributes<A>(attributes: &A) -> Option<&str>
    where
        A: AttributesMap;

    /// Read a string encoded attribute from the provided event attributes.
    fn raw_read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<&str, EventError>
    where
        A: AttributesMap;
}

impl<'value, DATA> RawReadFromEventAttributes<'value> for DATA
where
    DATA: EventAttributeEntry<'value>,
{
    #[inline]
    fn check_if_present_in<A>(attributes: &A) -> bool
    where
        A: AttributesMap,
    {
        attributes.is_attribute(DATA::KEY)
    }

    #[inline]
    fn raw_read_opt_from_event_attributes<A>(attributes: &A) -> Option<&str>
    where
        A: AttributesMap,
    {
        attributes.retrieve_attribute(DATA::KEY)
    }

    #[inline]
    fn raw_read_from_event_attributes<A>(
        attributes: &A,
    ) -> Result<&str, EventError>
    where
        A: AttributesMap,
    {
        Self::raw_read_opt_from_event_attributes(attributes).ok_or(
            EventError::MissingAttribute(
                <Self as EventAttributeEntry<'value>>::KEY,
            ),
        )
    }
}

/// Delete an attribute from an [event](Event)'s attributes.
pub trait DeleteFromEventAttributes {
    /// Delete an attribute from the provided event attributes.
    fn delete_from_event_attributes<A>(attributes: &mut A)
    where
        A: AttributesMap;
}

impl<'value, DATA> DeleteFromEventAttributes for DATA
where
    DATA: EventAttributeEntry<'value>,
{
    /// Delete an attribute from the provided event attributes.
    fn delete_from_event_attributes<A>(attributes: &mut A)
    where
        A: AttributesMap,
    {
        attributes.delete_attribute(DATA::KEY);
    }
}

/// Extend an [event](Event) with additional data.
pub trait ExtendEvent {
    /// Add additional data to the specified `event`.
    fn extend_event(self, event: &mut Event);
}

impl<E: ExtendEventAttributes> ExtendEvent for E {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        self.extend_event_attributes(&mut event.attributes);
    }
}

/// Extend an [`Event`] with block height information.
pub struct Height(pub BlockHeight);

impl EventAttributeEntry<'static> for Height {
    type Value = BlockHeight;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "height";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with the name of the wasm code.
pub struct CodeName(pub String);

impl EventAttributeEntry<'static> for CodeName {
    type Value = String;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "code-name";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with transaction hash information.
pub struct TxHash(pub Hash);

impl EventAttributeEntry<'static> for TxHash {
    type Value = Hash;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "hash";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with inner transaction hash information.
pub struct InnerTxHash(pub Hash);

impl EventAttributeEntry<'static> for InnerTxHash {
    type Value = Hash;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "inner-tx-hash";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with log data.
pub struct Log(pub String);

impl EventAttributeEntry<'static> for Log {
    type Value = String;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "log";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with info data.
pub struct Info(pub String);

impl EventAttributeEntry<'static> for Info {
    type Value = String;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "info";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with a new domain.
pub struct Domain<E>(PhantomData<E>);

/// Build a new [`Domain`] to extend an [event](Event) with.
pub const fn event_domain_of<E: EventToEmit>() -> Domain<E> {
    Domain(PhantomData)
}

/// Parsed domain of some [event](Event).
pub struct ParsedDomain<E> {
    domain: String,
    _marker: PhantomData<E>,
}

impl<E> ParsedDomain<E> {
    /// Return the inner domain as a [`String`].
    #[inline]
    pub fn into_inner(self) -> String {
        self.domain
    }
}

impl<E> From<ParsedDomain<E>> for String {
    #[inline]
    fn from(parsed_domain: ParsedDomain<E>) -> String {
        parsed_domain.into_inner()
    }
}

impl<E> FromStr for ParsedDomain<E>
where
    E: EventToEmit,
{
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == E::DOMAIN {
            Ok(Self {
                domain: s.to_owned(),
                _marker: PhantomData,
            })
        } else {
            Err(EventError::InvalidDomain(format!(
                "Expected {:?}, but found {s:?}",
                E::DOMAIN
            )))
        }
    }
}

impl<E> EventAttributeEntry<'static> for Domain<E>
where
    E: EventToEmit,
{
    type Value = &'static str;
    type ValueOwned = ParsedDomain<E>;

    const KEY: &'static str = "event-domain";

    fn into_value(self) -> Self::Value {
        E::DOMAIN
    }
}

/// Checks for the presence of an attribute in the
/// provided attributes map.
pub trait EventAttributeChecker<'value, A>
where
    A: AttributesMap,
{
    /// Check if the associated attribute is present in the provided event
    /// attributes.
    fn is_present(&self, attributes: &A) -> bool
    where
        A: AttributesMap;
}

/// Return a new implementation of [`EventAttributeChecker`].
pub fn attribute_checker<'value, DATA, ATTR>()
-> Box<dyn EventAttributeChecker<'value, ATTR>>
where
    DATA: EventAttributeEntry<'value> + 'static,
    ATTR: AttributesMap,
{
    Box::new(EventAttributeCheckerImpl(PhantomData::<DATA>))
}

/// Dispatch a callback on a list of attribute kinds.
pub fn dispatch_attribute<'value, I, K, A, F>(
    attributes: &A,
    dispatch_list: I,
    mut dispatch: F,
) where
    A: AttributesMap,
    I: IntoIterator<Item = (K, Box<dyn EventAttributeChecker<'value, A>>)>,
    F: FnMut(K) -> ControlFlow<()>,
{
    for (kind, checker) in dispatch_list {
        if !checker.is_present(attributes) {
            continue;
        }
        if let ControlFlow::Break(_) = dispatch(kind) {
            break;
        }
    }
}

struct EventAttributeCheckerImpl<DATA>(PhantomData<DATA>);

impl<'value, DATA, A> EventAttributeChecker<'value, A>
    for EventAttributeCheckerImpl<DATA>
where
    DATA: EventAttributeEntry<'value>,
    A: AttributesMap,
{
    fn is_present(&self, attributes: &A) -> bool
    where
        A: AttributesMap,
    {
        attributes.is_attribute(DATA::KEY)
    }
}

/// Extend an [`Event`] with the given closure.
pub struct Closure<F>(pub F);

impl<F> ExtendEvent for Closure<F>
where
    F: FnOnce(&mut Event),
{
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(closure) = self;
        closure(event);
    }
}

/// Implement the Display and FromStr traits for any serde type
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct EventValue<T>(pub T);

impl<T: Serialize> Display for EventValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ser =
            serde_json::to_string(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", ser)
    }
}

impl<T: for<'de> Deserialize<'de>> FromStr for EventValue<T> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map(Self)
    }
}

impl<T> From<T> for EventValue<T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

/// A user account.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum UserAccount {
    /// Internal chain address in Namada.
    Internal(Address),
    /// External chain address.
    External(String),
}

impl fmt::Display for UserAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal(addr) => write!(f, "internal-address/{addr}"),
            Self::External(addr) => write!(f, "external-address/{addr}"),
        }
    }
}

impl FromStr for UserAccount {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some(("internal-address", addr)) => {
                Ok(Self::Internal(Address::decode(addr).map_err(|err| {
                    format!(
                        "Unknown internal address balance change target \
                         {s:?}: {err}"
                    )
                })?))
            }
            Some(("external-address", addr)) => {
                Ok(Self::External(addr.to_owned()))
            }
            _ => Err(format!("Unknown balance change target {s:?}")),
        }
    }
}

impl serde::Serialize for UserAccount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UserAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod event_composition_tests {
    use super::*;

    struct DummyEvent;

    impl From<DummyEvent> for Event {
        fn from(_: DummyEvent) -> Event {
            Event::new(
                EventTypeBuilder::new_of::<DummyEvent>()
                    .with_segment("event")
                    .build(),
                EventLevel::Tx,
            )
        }
    }

    impl EventToEmit for DummyEvent {
        const DOMAIN: &'static str = "dummy";
    }

    #[test]
    fn test_event_height_parse() {
        let event: Event = DummyEvent.with(Height(BlockHeight(300))).into();

        let height = event.raw_read_attribute::<Height>().unwrap();
        assert_eq!(height, "300");
        assert_eq!(height.parse::<u64>().unwrap(), 300u64);

        let height = event.read_attribute::<Height>().unwrap();
        assert_eq!(height, BlockHeight(300));
    }

    #[test]
    fn test_event_compose_basic() {
        let expected_attrs = {
            let mut attrs = BTreeMap::new();
            attrs.insert("log".to_string(), "this is sparta!".to_string());
            attrs.insert("height".to_string(), "300".to_string());
            attrs.insert("hash".to_string(), Hash::default().to_string());
            attrs
        };

        let base_event: Event = DummyEvent
            .with(Log("this is sparta!".to_string()))
            .with(Height(300.into()))
            .with(TxHash(Hash::default()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_event_compose_repeated() {
        let expected_attrs = {
            let mut attrs = BTreeMap::new();
            attrs.insert("log".to_string(), "dejavu".to_string());
            attrs
        };

        let base_event: Event = DummyEvent
            .with(Log("dejavu".to_string()))
            .with(Log("dejavu".to_string()))
            .with(Log("dejavu".to_string()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_event_compose_last_one_kept() {
        let expected_attrs = {
            let mut attrs = BTreeMap::new();
            attrs.insert("log".to_string(), "last".to_string());
            attrs
        };

        let base_event: Event = DummyEvent
            .with(Log("fist".to_string()))
            .with(Log("second".to_string()))
            .with(Log("last".to_string()))
            .into();

        assert_eq!(base_event.attributes, expected_attrs);
    }

    #[test]
    fn test_event_attribute_dispatching() {
        enum AttrKind {
            Log,
            Info,
        }

        let attributes = {
            let mut attrs = BTreeMap::new();
            attrs.with_attribute(Info(String::new()));
            attrs
        };

        let log_attribute = attribute_checker::<Log, _>();
        let info_attribute = attribute_checker::<Info, _>();

        let mut found_info = false;
        let mut found_log = false;

        dispatch_attribute(
            &attributes,
            [
                (AttrKind::Info, info_attribute),
                (AttrKind::Log, log_attribute),
            ],
            |kind| {
                match kind {
                    AttrKind::Info => found_info = true,
                    AttrKind::Log => found_log = true,
                }
                ControlFlow::Continue(())
            },
        );

        assert!(found_info && !found_log);
    }
}
