// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// This file is part of Frontier.
//
// Copyright (c) 2015-2020 Parity Technologies (UK) Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Pub-Sub types.

use crate::types::{Filter, Log, RichHeader};
use ethereum_types::H256;
use futures::channel::mpsc;
use jsonrpc_pubsub::{PubSubMetadata, Session};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{from_value, Value};
use std::sync::Arc;

/// Subscription result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Result {
    /// New block header.
    Header(Box<RichHeader>),
    /// Log
    Log(Box<Log>),
    /// Transaction hash
    TransactionHash(H256),
    /// SyncStatus
    SyncState(PubSubSyncStatus),
}

/// PubSbub sync status
#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PubSubSyncStatus {
    /// is_major_syncing?
    pub syncing: bool,
}

impl Serialize for Result {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Result::Header(ref header) => header.serialize(serializer),
            Result::Log(ref log) => log.serialize(serializer),
            Result::TransactionHash(ref hash) => hash.serialize(serializer),
            Result::SyncState(ref sync) => sync.serialize(serializer),
        }
    }
}

/// Subscription kind.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    /// New block headers subscription.
    NewHeads,
    /// Logs subscription.
    Logs,
    /// New Pending Transactions subscription.
    NewPendingTransactions,
    /// Node syncing status subscription.
    Syncing,
}

/// Subscription kind.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Params {
    /// No parameters passed.
    None,
    /// Log parameters.
    Logs(Filter),
}

impl Default for Params {
    fn default() -> Self {
        Params::None
    }
}

impl<'a> Deserialize<'a> for Params {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Params, D::Error>
    where
        D: Deserializer<'a>,
    {
        let v: Value = Deserialize::deserialize(deserializer)?;

        if v.is_null() {
            return Ok(Params::None);
        }

        from_value(v)
            .map(Params::Logs)
            .map_err(|e| D::Error::custom(format!("Invalid Pub-Sub parameters: {e}")))
    }
}

/// RPC Metadata.
///
/// Manages persistent session for transports that support it
/// and may contain some additional info extracted from specific transports
/// (like remote client IP address, request headers, etc)
#[derive(Default, Clone)]
pub struct Metadata {
    session: Option<Arc<Session>>,
}

impl jsonrpc_core::Metadata for Metadata {}
impl PubSubMetadata for Metadata {
    fn session(&self) -> Option<Arc<Session>> {
        self.session.clone()
    }
}

impl Metadata {
    /// Create new `Metadata` with session (Pub/Sub) support.
    pub fn new(transport: mpsc::UnboundedSender<String>) -> Self {
        Metadata {
            session: Some(Arc::new(Session::new(transport))),
        }
    }

    /// Create new `Metadata` for tests.
    #[cfg(test)]
    pub fn new_test() -> (mpsc::UnboundedReceiver<String>, Self) {
        let (tx, rx) = mpsc::unbounded();
        (rx, Self::new(tx))
    }
}

impl From<mpsc::UnboundedSender<String>> for Metadata {
    fn from(sender: mpsc::UnboundedSender<String>) -> Self {
        Self::new(sender)
    }
}
