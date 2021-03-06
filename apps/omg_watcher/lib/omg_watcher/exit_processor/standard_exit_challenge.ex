# Copyright 2019 OmiseGO Pte Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule OMG.Watcher.ExitProcessor.StandardExitChallenge do
  @moduledoc """
  Part of Core to handle SE challenges & invalid exit detection.

  Treat as private helper submodule of `OMG.Watcher.ExitProcessor.Core`, test and call via that
  """

  # struct Represents a challenge to a standard exit
  defstruct [:exit_id, :txbytes, :input_index, :sig]

  @type t() :: %__MODULE__{
          exit_id: non_neg_integer(),
          txbytes: String.t(),
          input_index: non_neg_integer(),
          sig: String.t()
        }

  alias OMG.Block
  alias OMG.State.Transaction
  alias OMG.Utxo
  alias OMG.Watcher.ExitProcessor
  alias OMG.Watcher.ExitProcessor.Core
  alias OMG.Watcher.ExitProcessor.ExitInfo
  alias OMG.Watcher.ExitProcessor.Tools.DoubleSpend
  alias OMG.Watcher.ExitProcessor.Tools.KnownTx
  alias OMG.Watcher.ExitProcessor.TxAppendix

  import OMG.Watcher.ExitProcessor.Tools

  require Utxo

  @doc """
  Gets all utxo positions exiting via active standard exits
  """
  @spec exiting_positions(Core.t()) :: list(Utxo.Position.t())
  def exiting_positions(%Core{exits: exits}) do
    exits
    |> Enum.filter(fn {_key, %ExitInfo{is_active: is_active}} -> is_active end)
    |> Enum.map(fn {utxo_pos, _value} -> utxo_pos end)
  end

  @doc """
  Gets all standard exits that are invalid, all and late ones separately
  """
  @spec get_invalid(Core.t(), %{Utxo.Position.t() => boolean}, pos_integer()) ::
          {%{Utxo.Position.t() => ExitInfo.t()}, %{Utxo.Position.t() => ExitInfo.t()}}
  def get_invalid(%Core{exits: exits, sla_margin: sla_margin} = state, utxo_exists?, eth_height_now) do
    invalid_exit_positions =
      exits
      |> Enum.filter(fn {_key, %ExitInfo{is_active: is_active}} -> is_active end)
      |> Enum.map(fn {utxo_pos, _value} -> utxo_pos end)
      |> only_utxos_checked_and_missing(utxo_exists?)

    exits_invalid_by_ife = get_invalid_exits_based_on_ifes(state)
    invalid_exits = exits |> Map.take(invalid_exit_positions) |> Enum.concat(exits_invalid_by_ife) |> Enum.uniq()

    # get exits which are still invalid and after the SLA margin
    late_invalid_exits =
      invalid_exits
      |> Enum.filter(fn {_, %ExitInfo{eth_height: eth_height}} -> eth_height + sla_margin <= eth_height_now end)

    {Map.new(invalid_exits), Map.new(late_invalid_exits)}
  end

  @doc """
  Determines the utxo-creating and utxo-spending blocks to get from `OMG.DB`
  `se_spending_blocks_to_get` are requested by the UTXO position they spend
  `se_creating_blocks_to_get` are requested by blknum
  """
  @spec determine_standard_challenge_queries(ExitProcessor.Request.t(), Core.t()) ::
          {:ok, ExitProcessor.Request.t()} | {:error, :exit_not_found}
  def determine_standard_challenge_queries(
        %ExitProcessor.Request{se_exiting_pos: Utxo.position(creating_blknum, _, _) = exiting_pos} = request,
        %Core{exits: exits} = state
      ) do
    with %ExitInfo{} = _exit_info <- Map.get(exits, exiting_pos, {:error, :exit_not_found}) do
      spending_blocks_to_get = if get_ife_based_on_utxo(exiting_pos, state), do: [], else: [exiting_pos]
      creating_blocks_to_get = if Utxo.Position.is_deposit?(exiting_pos), do: [], else: [creating_blknum]

      {:ok,
       %ExitProcessor.Request{
         request
         | se_spending_blocks_to_get: spending_blocks_to_get,
           se_creating_blocks_to_get: creating_blocks_to_get
       }}
    end
  end

  @doc """
  Determines the txbytes of the particular transaction related to the SE - aka "output tx" - which creates the exiting
  utxo
  """
  @spec determine_exit_txbytes(ExitProcessor.Request.t(), Core.t()) ::
          ExitProcessor.Request.t()
  def determine_exit_txbytes(
        %ExitProcessor.Request{se_exiting_pos: exiting_pos, se_creating_blocks_result: creating_blocks_result} =
          request,
        %Core{exits: exits}
      ) do
    exit_id_to_get_by_txbytes =
      if Utxo.Position.is_deposit?(exiting_pos) do
        %ExitInfo{owner: owner, currency: currency, amount: amount} = exits[exiting_pos]
        Transaction.new([], [{owner, currency, amount}])
      else
        [%Block{transactions: transactions}] = creating_blocks_result
        Utxo.position(_, txindex, _) = exiting_pos

        {:ok, signed_bytes} = Enum.fetch(transactions, txindex)
        {:ok, tx} = Transaction.Signed.decode(signed_bytes)
        tx
      end
      |> Transaction.raw_txbytes()

    %ExitProcessor.Request{request | se_exit_id_to_get: exit_id_to_get_by_txbytes}
  end

  @doc """
  Creates the final challenge response, if possible
  """
  @spec create_challenge(ExitProcessor.Request.t(), Core.t()) ::
          {:ok, __MODULE__.t()} | {:error, :utxo_not_spent} | {:error, :exit_not_found}
  def create_challenge(
        %ExitProcessor.Request{
          se_exiting_pos: exiting_pos,
          se_spending_blocks_result: spending_blocks_result,
          se_exit_id_result: exit_id
        },
        %Core{exits: exits} = state
      ) do
    %ExitInfo{owner: owner} = exits[exiting_pos]
    ife_result = get_ife_based_on_utxo(exiting_pos, state)

    with {:ok, spending_tx_or_block} <- ensure_challengeable(spending_blocks_result, ife_result) do
      %DoubleSpend{known_spent_index: input_index, known_tx: %KnownTx{signed_tx: challenging_signed}} =
        get_double_spend_for_standard_exit(spending_tx_or_block, exiting_pos)

      {:ok,
       %__MODULE__{
         exit_id: exit_id,
         input_index: input_index,
         txbytes: challenging_signed |> Transaction.raw_txbytes(),
         sig: find_sig!(challenging_signed, owner)
       }}
    end
  end

  defp ensure_challengeable(spending_blknum_response, ife_response)

  defp ensure_challengeable([%Block{} = block], _), do: {:ok, block}
  defp ensure_challengeable(_, ife_response) when not is_nil(ife_response), do: {:ok, ife_response}
  defp ensure_challengeable(_, _), do: {:error, :utxo_not_spent}

  @spec get_ife_based_on_utxo(Utxo.Position.t(), Core.t()) :: KnownTx.t() | nil
  defp get_ife_based_on_utxo(Utxo.position(_, _, _) = utxo_pos, %Core{} = state) do
    state
    |> get_ife_txs()
    |> Enum.find(&get_double_spend_for_standard_exit(&1, utxo_pos))
  end

  # finds transaction in given block and input index spending given utxo
  @spec get_double_spend_for_standard_exit(Block.t() | KnownTx.t(), Utxo.Position.t()) :: DoubleSpend.t() | nil
  defp get_double_spend_for_standard_exit(%Block{transactions: txs}, utxo_pos) do
    txs
    |> Enum.map(&Transaction.Signed.decode/1)
    |> Enum.find_value(fn {:ok, tx} -> get_double_spend_for_standard_exit(%KnownTx{signed_tx: tx}, utxo_pos) end)
  end

  defp get_double_spend_for_standard_exit(%KnownTx{} = known_tx, utxo_pos) do
    Enum.at(get_double_spends_by_utxo_pos(utxo_pos, known_tx), 0)
  end

  # Gets all standard exits invalidated by IFEs exiting their utxo positions
  @spec get_invalid_exits_based_on_ifes(Core.t()) :: list(%{Utxo.Position.t() => ExitInfo.t()})
  defp get_invalid_exits_based_on_ifes(%Core{exits: exits} = state) do
    known_txs = get_ife_txs(state)

    exits
    # TODO: expensive!
    |> Enum.filter(fn {utxo_pos, _exit_info} -> Enum.find(known_txs, &get_double_spends_by_utxo_pos(utxo_pos, &1)) end)
  end

  @spec get_double_spends_by_utxo_pos(Utxo.Position.t(), KnownTx.t()) :: list(DoubleSpend.t())
  defp get_double_spends_by_utxo_pos(Utxo.position(_, _, oindex) = utxo_pos, known_tx),
    # the function used expects positions with an index (either input index or oindex), hence the oindex added
    do: [{utxo_pos, oindex}] |> double_spends_from_known_tx(known_tx)

  defp get_ife_txs(%Core{} = state) do
    TxAppendix.get_all(state)
    |> Enum.map(fn signed -> %KnownTx{signed_tx: signed} end)
  end
end
