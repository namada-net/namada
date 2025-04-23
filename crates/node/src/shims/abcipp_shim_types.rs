use crate::tendermint::abci::{Request, Response};

pub mod shim {
    use std::fmt::Debug;

    use thiserror::Error;

    use super::{Request as Req, Response as Resp};
    use crate::shell;
    use crate::tendermint::abci::{
        request as tm_request, response as tm_response,
    };

    pub type TxBytes = prost::bytes::Bytes;

    #[derive(Error, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Error {
        #[error("Error converting Request from ABCI to ABCI++: {0:?}")]
        ConvertReq(Req),
        #[error("Error converting Response from ABCI++ to ABCI: {0:?}")]
        ConvertResp(Response),
        #[error("{0:?}")]
        Shell(shell::Error),
    }

    /// Errors from the shell need to be propagated upward
    impl From<shell::Error> for Error {
        fn from(err: shell::Error) -> Self {
            Self::Shell(err)
        }
    }

    #[allow(clippy::large_enum_variant)]
    /// Our custom request types. It is the duty of the shim to change
    /// the request types coming from tower-abci to these before forwarding
    /// it to the shell
    ///
    /// Each request contains a custom payload type as well, which may
    /// be simply a unit struct
    pub enum Request {
        InitChain(tm_request::InitChain),
        Info(tm_request::Info),
        Query(tm_request::Query),
        PrepareProposal(tm_request::PrepareProposal),
        #[allow(dead_code)]
        VerifyHeader(request::VerifyHeader),
        ProcessProposal(tm_request::ProcessProposal),
        #[allow(dead_code)]
        RevertProposal(request::RevertProposal),
        FinalizeBlock(request::FinalizeBlock),
        Commit,
        Flush,
        Echo(tm_request::Echo),
        CheckTx(tm_request::CheckTx),
        ListSnapshots,
        OfferSnapshot(tm_request::OfferSnapshot),
        LoadSnapshotChunk(tm_request::LoadSnapshotChunk),
        ApplySnapshotChunk(tm_request::ApplySnapshotChunk),
    }

    /// Attempt to convert a tower-abci request to an internal one
    impl TryFrom<Req> for Request {
        type Error = Error;

        fn try_from(req: Req) -> Result<Request, Error> {
            match req {
                Req::InitChain(inner) => Ok(Request::InitChain(inner)),
                Req::Info(inner) => Ok(Request::Info(inner)),
                Req::Query(inner) => Ok(Request::Query(inner)),
                Req::Commit => Ok(Request::Commit),
                Req::Flush => Ok(Request::Flush),
                Req::Echo(inner) => Ok(Request::Echo(inner)),
                Req::CheckTx(inner) => Ok(Request::CheckTx(inner)),
                Req::ListSnapshots => Ok(Request::ListSnapshots),
                Req::OfferSnapshot(inner) => Ok(Request::OfferSnapshot(inner)),
                Req::LoadSnapshotChunk(inner) => {
                    Ok(Request::LoadSnapshotChunk(inner))
                }
                Req::ApplySnapshotChunk(inner) => {
                    Ok(Request::ApplySnapshotChunk(inner))
                }
                Req::PrepareProposal(inner) => {
                    Ok(Request::PrepareProposal(inner))
                }
                _ => Err(Error::ConvertReq(req)),
            }
        }
    }

    /// Custom response types.
    ///
    /// These will be returned by the shell along with
    /// custom payload types (which may be unit structs). It is the duty of
    /// the shim to convert these to responses understandable to tower-abci
    #[derive(Debug)]
    pub enum Response {
        InitChain(tm_response::InitChain),
        Info(tm_response::Info),
        Query(tm_response::Query),
        PrepareProposal(response::PrepareProposal),
        VerifyHeader(response::VerifyHeader),
        ProcessProposal(response::ProcessProposal),
        RevertProposal(response::RevertProposal),
        FinalizeBlock(response::FinalizeBlock),
        // EndBlock(tm_response::EndBlock),
        Commit(tm_response::Commit),
        Flush,
        Echo(tm_response::Echo),
        CheckTx(tm_response::CheckTx),
        ListSnapshots(tm_response::ListSnapshots),
        OfferSnapshot(tm_response::OfferSnapshot),
        LoadSnapshotChunk(tm_response::LoadSnapshotChunk),
        ApplySnapshotChunk(tm_response::ApplySnapshotChunk),
    }

    /// Attempt to convert response from shell to a tower-abci response type
    impl TryFrom<Response> for Resp {
        type Error = Error;

        fn try_from(resp: Response) -> Result<Resp, Error> {
            match resp {
                Response::InitChain(inner) => Ok(Resp::InitChain(inner)),
                Response::Info(inner) => Ok(Resp::Info(inner)),
                Response::Query(inner) => Ok(Resp::Query(inner)),
                Response::Commit(inner) => Ok(Resp::Commit(inner)),
                Response::Flush => Ok(Resp::Flush),
                Response::Echo(inner) => Ok(Resp::Echo(inner)),
                Response::CheckTx(inner) => Ok(Resp::CheckTx(inner)),
                Response::ListSnapshots(inner) => {
                    Ok(Resp::ListSnapshots(inner))
                }
                Response::OfferSnapshot(inner) => {
                    Ok(Resp::OfferSnapshot(inner))
                }
                Response::LoadSnapshotChunk(inner) => {
                    Ok(Resp::LoadSnapshotChunk(inner))
                }
                Response::ApplySnapshotChunk(inner) => {
                    Ok(Resp::ApplySnapshotChunk(inner))
                }
                Response::PrepareProposal(inner) => {
                    Ok(Resp::PrepareProposal(inner))
                }
                Response::ProcessProposal(inner) => {
                    Ok(Resp::ProcessProposal(inner))
                }
                _ => Err(Error::ConvertResp(resp)),
            }
        }
    }

    /// Custom types for request payloads
    pub mod request {

        use bytes::Bytes;
        use namada_sdk::hash::Hash;
        use namada_sdk::storage::BlockHeader;
        use namada_sdk::tendermint::abci::types::CommitInfo;
        use namada_sdk::tendermint::account::Id;
        use namada_sdk::tendermint::block::Height;
        use namada_sdk::tendermint::time::Time;
        use namada_sdk::time::DateTimeUtc;

        use crate::tendermint::abci::request as tm_request;
        use crate::tendermint::abci::types::Misbehavior;

        pub struct VerifyHeader;

        pub struct RevertProposal;

        /// A Tx and the result of calling Process Proposal on it
        #[derive(Debug, Clone)]
        pub struct ProcessedTx {
            pub tx: super::TxBytes,
            pub result: super::response::TxResult,
        }

        #[derive(Debug, Clone)]
        pub struct FinalizeBlock {
            pub header: BlockHeader,
            pub block_hash: Hash,
            pub byzantine_validators: Vec<Misbehavior>,
            pub txs: Vec<ProcessedTx>,
            pub proposer_address: Vec<u8>,
            pub height: Height,
            pub decided_last_commit: CommitInfo,
        }

        // Type to run process proposal checks outside of the CometBFT call
        pub(crate) struct CheckProcessProposal {
            proposed_last_commit: Option<CommitInfo>,
            misbehavior: Vec<Misbehavior>,
            hash: namada_sdk::tendermint::Hash,
            height: Height,
            time: Time,
            next_validators_hash: namada_sdk::tendermint::Hash,
            proposer_address: Id,
            txs: Vec<Bytes>,
        }

        impl From<tm_request::FinalizeBlock> for FinalizeBlock {
            fn from(req: tm_request::FinalizeBlock) -> FinalizeBlock {
                FinalizeBlock {
                    header: BlockHeader {
                        #[allow(clippy::disallowed_methods)]
                        hash: Hash::try_from(req.hash.as_bytes())
                            .unwrap_or_default(),
                        time: DateTimeUtc::try_from(req.time).unwrap(),
                        next_validators_hash: req
                            .next_validators_hash
                            .try_into()
                            .unwrap(),
                    },
                    block_hash: req.hash.try_into().unwrap(),
                    byzantine_validators: req.misbehavior,
                    txs: vec![], // TODO  missing result here, it's filled in
                    // `AbcippShim::run` with the attached results
                    proposer_address: req.proposer_address.into(),
                    height: req.height,
                    decided_last_commit: req.decided_last_commit,
                }
            }
        }

        impl From<tm_request::FinalizeBlock> for CheckProcessProposal {
            fn from(req: tm_request::FinalizeBlock) -> CheckProcessProposal {
                CheckProcessProposal {
                    proposed_last_commit: Some(req.decided_last_commit),
                    misbehavior: req.misbehavior,
                    hash: req.hash,
                    height: req.height,
                    time: req.time,
                    next_validators_hash: req.next_validators_hash,
                    proposer_address: req.proposer_address,
                    txs: req.txs,
                }
            }
        }

        impl CheckProcessProposal {
            pub(crate) fn cast_to_tendermint_req(
                self,
            ) -> tm_request::ProcessProposal {
                let Self {
                    txs,
                    proposed_last_commit,
                    misbehavior,
                    hash,
                    height,
                    time,
                    next_validators_hash,
                    proposer_address,
                } = self;

                tm_request::ProcessProposal {
                    txs,
                    proposed_last_commit,
                    misbehavior,
                    hash,
                    height,
                    time,
                    next_validators_hash,
                    proposer_address,
                }
            }
        }

        impl FinalizeBlock {
            #[allow(clippy::result_large_err)]
            pub(crate) fn cast_to_process_proposal_req(
                self,
            ) -> Result<tm_request::ProcessProposal, super::Error> {
                let header = self.header;
                Ok(tm_request::ProcessProposal {
                    txs: self.txs.into_iter().map(|tx| tx.tx).collect(),
                    proposed_last_commit: Some(self.decided_last_commit),
                    misbehavior: self.byzantine_validators,
                    hash: self.block_hash.into(),
                    height: self.height,
                    time: header.time.try_into().map_err(|_| {
                        super::Error::Shell(
                            super::shell::Error::InvalidBlockProposal,
                        )
                    })?,
                    next_validators_hash: header.next_validators_hash.into(),
                    proposer_address: self
                        .proposer_address
                        .try_into()
                        .map_err(|_| {
                            super::Error::Shell(
                                super::shell::Error::InvalidBlockProposal,
                            )
                        })?,
                })
            }
        }
    }

    /// Custom types for response payloads
    pub mod response {
        use namada_sdk::events::Event;
        use namada_sdk::tendermint;

        use crate::tendermint::abci::Event as TmEvent;
        pub use crate::tendermint::abci::response::{
            PrepareProposal, ProcessProposal,
        };

        #[derive(Debug, Default)]
        pub struct VerifyHeader;

        #[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
        pub struct TxResult {
            pub code: u32,
            pub info: String,
        }

        #[derive(Debug, Default)]
        pub struct RevertProposal;

        #[derive(Debug, Default)]
        pub struct FinalizeBlock {
            pub events: Vec<Event>,
            pub validator_updates: Vec<tendermint::validator::Update>,
            pub consensus_param_updates: Option<tendermint::consensus::Params>,
            pub tx_results: Vec<tendermint::abci::types::ExecTxResult>,
            pub app_hash: tendermint::AppHash,
        }

        impl From<FinalizeBlock> for tendermint::abci::response::FinalizeBlock {
            fn from(resp: FinalizeBlock) -> Self {
                Self {
                    events: resp
                        .events
                        .into_iter()
                        .map(TmEvent::from)
                        .collect(),
                    validator_updates: resp.validator_updates,
                    consensus_param_updates: resp.consensus_param_updates,
                    tx_results: resp.tx_results,
                    app_hash: resp.app_hash,
                }
            }
        }

        impl From<(u32, String)> for TxResult {
            fn from(value: (u32, String)) -> Self {
                Self {
                    code: value.0,
                    info: value.1,
                }
            }
        }

        impl From<TxResult> for (u32, String) {
            fn from(value: TxResult) -> Self {
                (value.code, value.info)
            }
        }
    }
}
