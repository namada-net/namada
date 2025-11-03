use std::io::Read;

use color_eyre::eyre::Result;
use namada_sdk::io::{Io, NamadaIo, display_line};
use namada_sdk::masp::ShieldedContext;
use namada_sdk::{Namada, NamadaImpl};
use namada_wallet::DatedViewingKey;

use crate::cli;
use crate::cli::api::{CliApi, CliClient};
use crate::cli::args::CliToSdk;
use crate::cli::cmds::*;
use crate::client::{rpc, tx, utils};

impl CliApi {
    pub async fn handle_client_command<C, IO: Io + Send + Sync>(
        client: Option<C>,
        cmd: cli::NamadaClient,
        io: IO,
    ) -> Result<()>
    where
        C: CliClient + Clone,
    {
        match cmd {
            cli::NamadaClient::WithContext(cmd_box) => {
                let (cmd, mut ctx) = *cmd_box;
                use NamadaClientWithContext as Sub;
                match cmd {
                    // Ledger cmds
                    Sub::TxCustom(TxCustom(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        let dry_run = args.tx.dry_run.is_some();
                        tx::submit_custom(&namada, args).await?;
                        if !dry_run {
                            namada
                                .wallet()
                                .await
                                .save()
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            namada.io().println(
                                "Transaction dry run. No addresses have been \
                                 saved.",
                            )
                        }
                    }
                    Sub::TxTransparentTransfer(TxTransparentTransfer(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_transparent_transfer(&namada, args).await?;
                    }
                    Sub::TxShieldedTransfer(TxShieldedTransfer(args)) => {
                        let extra_sync_vks = {
                            let chain_ctx = ctx.borrow_chain_or_exit();
                            chain_ctx
                                .wallet
                                .get_viewing_keys()
                                .into_iter()
                                .map(|(k, v)| {
                                    DatedViewingKey::new(
                                        v,
                                        chain_ctx
                                            .wallet
                                            .find_birthday(k)
                                            .copied(),
                                    )
                                })
                                .collect::<Vec<_>>()
                        };
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let shielded = std::mem::take(&mut chain_ctx.shielded);
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;

                        let mut args = args.to_sdk(&mut ctx)?;
                        let mut sync_args = std::mem::take(
                            &mut args.shielded_sync,
                        )
                        .expect("Missing required shielded-sync arguments");
                        sync_args.viewing_keys.extend(extra_sync_vks);
                        let shielded = crate::client::masp::syncing(
                            ShieldedContext::new(shielded),
                            client.clone(),
                            sync_args,
                            &io,
                        )
                        .await?;

                        let namada = ctx.to_sdk(client, io);
                        let namada =
                            namada.update_shielded_context(shielded).await;
                        tx::submit_shielded_transfer(&namada, args).await?;
                    }
                    Sub::TxShieldingTransfer(TxShieldingTransfer(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_shielding_transfer(&namada, args).await?;
                    }
                    Sub::TxUnshieldingTransfer(TxUnshieldingTransfer(args)) => {
                        let extra_sync_vks = {
                            let chain_ctx = ctx.borrow_chain_or_exit();
                            chain_ctx
                                .wallet
                                .get_viewing_keys()
                                .into_iter()
                                .map(|(k, v)| {
                                    DatedViewingKey::new(
                                        v,
                                        chain_ctx
                                            .wallet
                                            .find_birthday(k)
                                            .copied(),
                                    )
                                })
                                .collect::<Vec<_>>()
                        };
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let shielded = std::mem::take(&mut chain_ctx.shielded);
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;

                        let mut args = args.to_sdk(&mut ctx)?;
                        let mut sync_args = std::mem::take(
                            &mut args.shielded_sync,
                        )
                        .expect("Missing required shielded-sync arguments");
                        sync_args.viewing_keys.extend(extra_sync_vks);
                        let shielded = crate::client::masp::syncing(
                            ShieldedContext::new(shielded),
                            client.clone(),
                            sync_args,
                            &io,
                        )
                        .await?;

                        let namada = ctx.to_sdk(client, io);
                        let namada =
                            namada.update_shielded_context(shielded).await;
                        tx::submit_unshielding_transfer(&namada, args).await?;
                    }
                    Sub::TxIbcTransfer(args) => {
                        let TxIbcTransfer(args) = *args;
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let shielded = std::mem::take(&mut chain_ctx.shielded);
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;

                        let mut args = args.to_sdk(&mut ctx)?;
                        if args.source.spending_key().is_some() {
                            // Sync the shielded context
                            let chain_ctx = ctx.borrow_chain_or_exit();
                            let extra_sync_vks = chain_ctx
                                .wallet
                                .get_viewing_keys()
                                .into_iter()
                                .map(|(k, v)| {
                                    DatedViewingKey::new(
                                        v,
                                        chain_ctx
                                            .wallet
                                            .find_birthday(k)
                                            .copied(),
                                    )
                                })
                                .collect::<Vec<_>>();
                            let mut sync_args = std::mem::take(
                                &mut args.shielded_sync,
                            )
                            .expect("Missing required shielded-sync arguments");
                            sync_args.viewing_keys.extend(extra_sync_vks);
                            let synced_shielded_ctx =
                                crate::client::masp::syncing(
                                    ShieldedContext::new(shielded),
                                    client.clone(),
                                    sync_args,
                                    &io,
                                )
                                .await?;

                            let namada = ctx
                                .to_sdk(client, io)
                                .update_shielded_context(synced_shielded_ctx)
                                .await;
                            tx::submit_ibc_transfer(&namada, args).await?
                        } else {
                            let namada = ctx.to_sdk(client, io);
                            tx::submit_ibc_transfer(&namada, args).await?
                        }
                    }
                    Sub::TxOsmosisSwap(args) => {
                        let TxOsmosisSwap(args) = *args;
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.transfer.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;

                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        let args = args
                            .into_ibc_transfer(
                                &namada,
                                |_route, min_amount, quote_amount| {
                                    use std::io::Write;

                                    if let Some(quote_amount) = quote_amount {
                                        print!(
                                            "Minimum output is {min_amount}, \
                                             while the quote price is \
                                             {quote_amount}, proceed with \
                                             trade (y/n)? "
                                        );
                                    } else {
                                        print!(
                                            "Minimum output is {min_amount}, \
                                             proceed with trade (y/n)? "
                                        );
                                    }

                                    std::io::stdout()
                                        .flush()
                                        .expect("Failed to flush stdout");

                                    let line = {
                                        let mut line = String::new();
                                        std::io::stdin()
                                            .read_line(&mut line)
                                            .expect(
                                                "Failed to read line from \
                                                 stdin",
                                            );
                                        line
                                    };

                                    matches!(
                                        line.trim(),
                                        "y" | "Y" | "yes" | "YES" | "Yes"
                                    )
                                },
                            )
                            .await?;

                        tx::submit_ibc_transfer(&namada, args).await?;
                    }
                    Sub::TxUpdateAccount(TxUpdateAccount(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_update_account(&namada, args).await?;
                    }
                    Sub::TxInitAccount(TxInitAccount(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        let dry_run = args.tx.dry_run.is_some();
                        tx::submit_init_account(&namada, args).await?;
                        if !dry_run {
                            namada
                                .wallet()
                                .await
                                .save()
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            namada.io().println(
                                "Transaction dry run. No addresses have been \
                                 saved.",
                            )
                        }
                    }
                    Sub::TxBecomeValidator(TxBecomeValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let cli::context::ChainContext {
                            wallet,
                            mut config,
                            shielded,
                            native_token,
                        } = ctx.take_chain_or_exit();
                        let namada = NamadaImpl::native_new(
                            client,
                            wallet,
                            shielded,
                            io,
                            native_token,
                        );
                        tx::submit_become_validator(&namada, &mut config, args)
                            .await?;
                    }
                    Sub::TxInitValidator(TxInitValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let cli::context::ChainContext {
                            wallet,
                            mut config,
                            shielded,
                            native_token,
                        } = ctx.take_chain_or_exit();
                        let namada = NamadaImpl::native_new(
                            client,
                            wallet,
                            shielded,
                            io,
                            native_token,
                        );
                        tx::submit_init_validator(&namada, &mut config, args)
                            .await?;
                    }
                    Sub::TxInitProposal(TxInitProposal(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_init_proposal(&namada, args).await?;
                    }
                    Sub::TxVoteProposal(TxVoteProposal(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_vote_proposal(&namada, args).await?;
                    }
                    Sub::TxRevealPk(TxRevealPk(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_reveal_pk(&namada, args).await?;
                    }
                    Sub::Bond(Bond(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_bond(&namada, args).await?;
                    }
                    Sub::Unbond(Unbond(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_unbond(&namada, args).await?;
                    }
                    Sub::Withdraw(Withdraw(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_withdraw(&namada, args).await?;
                    }
                    Sub::ClaimRewards(ClaimRewards(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_claim_rewards(&namada, args).await?;
                    }
                    Sub::Redelegate(Redelegate(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_redelegate(&namada, args).await?;
                    }
                    Sub::TxCommissionRateChange(TxCommissionRateChange(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_validator_commission_change(&namada, args)
                            .await?;
                    }
                    Sub::TxChangeConsensusKey(TxChangeConsensusKey(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_change_consensus_key(&namada, args).await?;
                    }
                    Sub::TxMetadataChange(TxMetadataChange(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_validator_metadata_change(&namada, args)
                            .await?;
                    }
                    Sub::ShieldedSync(ShieldedSync(args)) => {
                        let mut args = args.to_sdk(&mut ctx)?;
                        let chain_ctx = ctx.take_chain_or_exit();
                        let client = client.unwrap();
                        if args.with_indexer.is_none() {
                            client.wait_until_node_is_synced(&io).await?;
                        }
                        args.viewing_keys.extend(
                            chain_ctx
                                .wallet
                                .get_viewing_keys()
                                .into_iter()
                                .map(|(k, v)| {
                                    DatedViewingKey::new(
                                        v,
                                        chain_ctx
                                            .wallet
                                            .find_birthday(k)
                                            .copied(),
                                    )
                                }),
                        );

                        crate::client::masp::syncing(
                            ShieldedContext::new(chain_ctx.shielded),
                            client,
                            args,
                            &io,
                        )
                        .await?;
                    }
                    Sub::GenIbcShieldingTransfer(GenIbcShieldingTransfer(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::gen_ibc_shielding_transfer(&namada, args).await?;
                    }
                    #[cfg(feature = "namada-eth-bridge")]
                    Sub::AddToEthBridgePool(args) => {
                        let args = args.0;
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_bridge_pool_tx(&namada, args).await?;
                    }
                    #[cfg(not(feature = "namada-eth-bridge"))]
                    Sub::AddToEthBridgePool(_) => {
                        display_line!(
                            &io,
                            "The Namada Ethereum bridge is disabled"
                        );
                    }
                    Sub::TxUnjailValidator(TxUnjailValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_unjail_validator(&namada, args).await?;
                    }
                    Sub::TxDeactivateValidator(TxDeactivateValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_deactivate_validator(&namada, args).await?;
                    }
                    Sub::TxReactivateValidator(TxReactivateValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_reactivate_validator(&namada, args).await?;
                    }
                    Sub::TxUpdateStewardCommission(
                        TxUpdateStewardCommission(args),
                    ) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_update_steward_commission(&namada, args)
                            .await?;
                    }
                    Sub::TxResignSteward(TxResignSteward(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_resign_steward(&namada, args).await?;
                    }
                    // Ledger queries
                    Sub::QueryEpoch(QueryEpoch(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_epoch(&namada).await;
                        rpc::query_and_print_masp_epoch(&namada).await;
                    }
                    Sub::QueryNextEpochInfo(QueryNextEpochInfo(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_next_epoch_info(&namada).await;
                    }
                    Sub::QueryStatus(QueryStatus(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_status(&namada).await;
                    }
                    Sub::QueryValidatorState(QueryValidatorState(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_validator_state(&namada, args)
                            .await;
                    }
                    Sub::QueryConversions(QueryConversions(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_conversions(&namada, args).await;
                    }
                    Sub::QueryMaspRewardTokens(QueryMaspRewardTokens(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_masp_reward_tokens(&namada).await;
                    }
                    Sub::QueryBlock(QueryBlock(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_block(&namada).await;
                    }
                    Sub::QueryBalance(QueryBalance(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let shielded = std::mem::take(&mut chain_ctx.shielded);
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;

                        let mut args = args.to_sdk(&mut ctx)?;
                        if args.owner.full_viewing_key().is_some() {
                            // Sync the shielded context
                            let chain_ctx = ctx.borrow_chain_or_exit();
                            let extra_sync_vks = chain_ctx
                                .wallet
                                .get_viewing_keys()
                                .into_iter()
                                .map(|(k, v)| {
                                    DatedViewingKey::new(
                                        v,
                                        chain_ctx
                                            .wallet
                                            .find_birthday(k)
                                            .copied(),
                                    )
                                })
                                .collect::<Vec<_>>();
                            let mut sync_args = std::mem::take(
                                &mut args.shielded_sync,
                            )
                            .expect("Missing required shielded-sync arguments");
                            sync_args.viewing_keys.extend(extra_sync_vks);
                            let synced_shielded_ctx =
                                crate::client::masp::syncing(
                                    ShieldedContext::new(shielded),
                                    client.clone(),
                                    sync_args,
                                    &io,
                                )
                                .await?;

                            let namada = ctx
                                .to_sdk(client, io)
                                .update_shielded_context(synced_shielded_ctx)
                                .await;
                            rpc::query_balance(&namada, args).await;
                        } else {
                            let namada = ctx.to_sdk(client, io);
                            rpc::query_balance(&namada, args).await;
                        }
                    }
                    Sub::QueryShieldingRewardsEstimate(
                        QueryShieldingRewardsEstimate(args),
                    ) => {
                        let extra_sync_vks = {
                            let chain_ctx = ctx.borrow_chain_or_exit();
                            chain_ctx
                                .wallet
                                .get_viewing_keys()
                                .into_iter()
                                .map(|(k, v)| {
                                    DatedViewingKey::new(
                                        v,
                                        chain_ctx
                                            .wallet
                                            .find_birthday(k)
                                            .copied(),
                                    )
                                })
                                .collect::<Vec<_>>()
                        };
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let shielded = std::mem::take(&mut chain_ctx.shielded);
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;

                        let mut args = args.to_sdk(&mut ctx)?;
                        let mut sync_args = std::mem::take(
                            &mut args.shielded_sync,
                        )
                        .expect("Missing required shielded-sync arguments");
                        sync_args.viewing_keys.extend(extra_sync_vks);
                        let shielded = crate::client::masp::syncing(
                            ShieldedContext::new(shielded),
                            client.clone(),
                            sync_args,
                            &io,
                        )
                        .await?;

                        let namada = ctx.to_sdk(client, io);
                        let namada =
                            namada.update_shielded_context(shielded).await;
                        rpc::query_rewards_estimate(&namada, args).await;
                    }
                    Sub::QueryBonds(QueryBonds(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_bonds(&namada, args)
                            .await
                            .expect("expected successful query of bonds");
                    }
                    Sub::QueryBondedStake(QueryBondedStake(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_bonded_stake(&namada, args).await;
                    }
                    Sub::QueryCommissionRate(QueryCommissionRate(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_commission_rate(&namada, args)
                            .await;
                    }
                    Sub::QueryMetaData(QueryMetaData(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_metadata(&namada, args).await;
                    }
                    Sub::QuerySlashes(QuerySlashes(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_slashes(&namada, args).await;
                    }
                    Sub::QueryRewards(QueryRewards(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_rewards(&namada, args).await;
                    }
                    Sub::QueryDelegations(QueryDelegations(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_delegations(&namada, args).await;
                    }
                    Sub::QueryTotalSupply(QueryTotalSupply(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_total_supply(&namada, args).await;
                    }
                    Sub::QueryEffNativeSupply(QueryEffNativeSupply(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_effective_native_supply(&namada).await;
                    }
                    Sub::QueryStakingRewardsRate(QueryStakingRewardsRate(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_staking_rewards_rate(&namada).await;
                    }
                    Sub::QueryFindValidator(QueryFindValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_find_validator(&namada, args).await;
                    }
                    Sub::QueryResult(QueryResult(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_result(&namada, args).await;
                    }
                    Sub::QueryRawBytes(QueryRawBytes(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_raw_bytes(&namada, args).await;
                    }
                    Sub::QueryProposal(QueryProposal(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_proposal(&namada, args).await;
                    }
                    Sub::QueryProposalResult(QueryProposalResult(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_proposal_result(&namada, args).await;
                    }
                    Sub::QueryProposalVotes(QueryProposalVotes(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_proposal_votes(&namada, args).await;
                    }
                    Sub::QueryProtocolParameters(QueryProtocolParameters(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_protocol_parameters(&namada, args).await;
                    }
                    Sub::QueryPgf(QueryPgf(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_pgf(&namada, args).await;
                    }
                    Sub::QueryAccount(QueryAccount(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_account(&namada, args).await;
                    }
                    Sub::QueryIbcRateLimit(QueryIbcRateLimit(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_ibc_rate_limits(&namada, args).await;
                    }
                }
            }
            cli::NamadaClient::WithoutContext(cmd_box) => {
                let (cmd, global_args) = *cmd_box;
                match cmd {
                    // Utils cmds
                    ClientUtils::JoinNetwork(JoinNetwork(args)) => {
                        utils::join_network(global_args, args).await
                    }
                    ClientUtils::ValidateWasm(ValidateWasm(args)) => {
                        utils::validate_wasm(args)
                    }
                    ClientUtils::InitNetwork(InitNetwork(args)) => {
                        utils::init_network(global_args, args);
                    }
                    ClientUtils::GenesisBond(GenesisBond(args)) => {
                        utils::genesis_bond(global_args, args)
                    }
                    ClientUtils::DeriveGenesisAddresses(
                        DeriveGenesisAddresses(args),
                    ) => utils::derive_genesis_addresses(global_args, args),
                    ClientUtils::InitGenesisEstablishedAccount(
                        InitGenesisEstablishedAccount(args),
                    ) => utils::init_genesis_established_account(
                        global_args,
                        args,
                    ),
                    ClientUtils::InitGenesisValidator(
                        InitGenesisValidator(args),
                    ) => utils::init_genesis_validator(global_args, args),
                    ClientUtils::PkToTmAddress(PkToTmAddress(args)) => {
                        utils::pk_to_tm_address(global_args, args)
                    }
                    ClientUtils::SignOffline(SignOffline(args)) => {
                        let mut ctx = cli::Context::new::<IO>(global_args)
                            .expect("expected to construct a context");
                        let args = args.to_sdk(&mut ctx)?;
                        utils::sign_offline(args).await
                    }
                    ClientUtils::DefaultBaseDir(DefaultBaseDir(args)) => {
                        utils::default_base_dir(global_args, args)
                    }
                    ClientUtils::EpochSleep(EpochSleep(args)) => {
                        let mut ctx = cli::Context::new::<IO>(global_args)
                            .expect("expected to construct a context");
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client =
                            C::from_tendermint_address(&ledger_address);
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::epoch_sleep(&namada, args).await;
                    }
                    ClientUtils::ValidateGenesisTemplates(
                        ValidateGenesisTemplates(args),
                    ) => utils::validate_genesis_templates(global_args, args),
                    ClientUtils::SignGenesisTxs(SignGenesisTxs(args)) => {
                        utils::sign_genesis_tx(global_args, args).await
                    }
                    ClientUtils::ParseMigrationJson(MigrationJson(args)) => {
                        #[cfg(feature = "migrations")]
                        {
                            let mut update_json = String::new();
                            let mut file = std::fs::File::open(args.path)
                                .expect(
                                    "Could not fine updates file at the \
                                     specified path.",
                                );
                            file.read_to_string(&mut update_json)
                                .expect("Unable to read the updates json file");
                            let updates: namada_sdk::migrations::DbChanges =
                                serde_json::from_str(&update_json).expect(
                                    "Could not parse the updates file as json",
                                );
                            for change in updates.changes {
                                display_line!(io, "{}", change);
                            }
                        }
                        #[cfg(not(feature = "migrations"))]
                        {
                            display_line!(
                                io,
                                "Can only use this function if compiled with \
                                 feature \"migrations\" enabled."
                            )
                        }
                    }
                    ClientUtils::DeriveIbcToken(DeriveIbcToken(args)) => {
                        utils::derive_ibc_token_address(args);
                    }
                    ClientUtils::PubKeyToAddr(PubKeyToAddr(args)) => {
                        utils::pubkey_to_address(args);
                    }
                }
            }
        }
        Ok(())
    }
}
