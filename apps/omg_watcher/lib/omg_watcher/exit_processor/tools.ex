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

defmodule OMG.Watcher.ExitProcessor.Tools do
  @moduledoc """
  Private tools that various components of the `ExitProcessor` share
  """

  alias OMG.Crypto
  alias OMG.State.Transaction
  alias OMG.TypedDataHash
  alias OMG.Utxo

  require Utxo

  defmodule KnownTx do
    @moduledoc """
    Wrapps information about a particular signed transaction known from somewhere, optionally with its UTXO position

    Private
    """
    defstruct [:signed_tx, :utxo_pos]

    alias OMG.Watcher.ExitProcessor.Tools

    @type t() :: %__MODULE__{
            signed_tx: Transaction.Signed.t(),
            utxo_pos: Utxo.Position.t() | nil
          }

    @doc """


    When grouping it keeps only the oldest transaction found
    """
    # FIXME docs
    def group_txs_by_input(all_known_txs) do
      all_known_txs
      # FIXME: streamify? remove the empty map too
      |> Enum.map(& &1)
      |> IO.inspect()
      |> Enum.map(&{&1, Transaction.get_inputs(&1.signed_tx)})
      |> Enum.flat_map(fn {known_tx, inputs} -> for input <- inputs, do: {input, known_tx} end)
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      # FIXME this
      # this should not be necessary - group_by preserves order and the all_known_txs were sorted on start but rethink
      |> Enum.into(%{}, fn {input, known_txs} -> {input, Enum.sort(known_txs, &is_older?/2)} end)
      |> IO.inspect()
    end

    # FIXME: unused now, remove
    defp group_picking_only_oldest(stream) do
      stream
      |> Enum.reduce(%{}, fn {input, %KnownTx{} = known_tx}, acc ->
        Map.update(acc, input, known_tx, fn current_oldest_known_tx ->
          case current_oldest_known_tx do
            nil -> known_tx
            _ -> if is_older?(known_tx, current_oldest_known_tx), do: known_tx, else: current_oldest_known_tx
          end
        end)
      end)
    end

    @doc """


    `known_txs_by_input` are assumed to hold _the oldest_ transaction spending given input for every input
    """
    # FIXME docs
    def find_competitor(known_txs_by_input, tx) do
      inputs = Transaction.get_inputs(tx)

      known_txs_by_input
      |> Map.take(inputs)
      # FIXME: consider streamifying
      |> Enum.map(fn {_input, spending_txs} -> spending_txs end)
      |> Enum.filter(&Tools.txs_different(tx, &1.signed_tx))
      |> Enum.sort(&is_older?/2)
      |> Enum.at(0)
      |> case do
        nil -> nil
        known_tx -> inputs |> Enum.with_index() |> Tools.double_spends_from_known_tx(known_tx) |> hd()
      end
    end

    defp is_older?(%KnownTx{utxo_pos: utxo_pos1}, %KnownTx{utxo_pos: utxo_pos2}) do
      cond do
        is_nil(utxo_pos1) -> false
        is_nil(utxo_pos2) -> true
        true -> Utxo.Position.encode(utxo_pos1) < Utxo.Position.encode(utxo_pos2)
      end
    end
  end

  defmodule DoubleSpend do
    @moduledoc """
    Wraps information about a single double spend occuring between a verified transaction and a known transaction
    """

    defstruct [:index, :utxo_pos, :known_spent_index, :known_tx]

    @type t() :: %__MODULE__{
            index: non_neg_integer(),
            utxo_pos: Utxo.Position.t(),
            known_spent_index: non_neg_integer,
            known_tx: KnownTx.t()
          }
  end

  # Intersects utxos, looking for duplicates. Gives full list of double-spends with indexes for
  # a pair of transactions.
  @spec double_spends_from_known_tx(list({Utxo.Position.t(), non_neg_integer()}), KnownTx.t()) ::
          list(DoubleSpend.t())
  def double_spends_from_known_tx(inputs, %KnownTx{signed_tx: signed} = known_tx) when is_list(inputs) do
    known_spent_inputs = signed |> Transaction.get_inputs() |> Enum.with_index()

    # TODO: possibly ineffective if Transaction.max_inputs >> 4
    for {left, left_index} <- inputs,
        {right, right_index} <- known_spent_inputs,
        left == right,
        do: %DoubleSpend{index: left_index, utxo_pos: left, known_spent_index: right_index, known_tx: known_tx}
  end

  # based on an enumberable of `Utxo.Position` and a mapping that tells whether one exists it will pick
  # only those that **were checked** and were missing
  # (i.e. those not checked are assumed to be present)
  def only_utxos_checked_and_missing(utxo_positions, utxo_exists?) do
    # the default value below is true, so that the assumption is that utxo not checked is **present**
    # TODO: rather inefficient, but no as inefficient as the nested `filter` calls in searching for competitors
    #       consider optimizing using `MapSet`

    Enum.filter(utxo_positions, fn utxo_pos -> !Map.get(utxo_exists?, utxo_pos, true) end)
  end

  @doc """
  Finds the exact signature which signed the particular transaction for the given owner address
  """
  @spec find_sig(Transaction.Signed.t(), Crypto.address_t()) :: {:ok, Crypto.sig_t()} | nil
  def find_sig(%Transaction.Signed{sigs: sigs, raw_tx: raw_tx}, owner) do
    tx_hash = TypedDataHash.hash_struct(raw_tx)

    Enum.find(sigs, fn sig ->
      {:ok, owner} == Crypto.recover_address(tx_hash, sig)
    end)
    |> case do
      nil -> nil
      other -> {:ok, other}
    end
  end

  @doc """
  Throwing version of `find_sig/2`

  At some point having a tx that wasn't actually signed is an error, hence pattern match
  if `find_sig/2` returns nil it means somethings very wrong - the owner taken (effectively) from the contract
  doesn't appear to have signed the potential competitor, which means that some prior signature checking was skipped
  """
  def find_sig!(tx, owner) do
    {:ok, sig} = find_sig(tx, owner)
    sig
  end

  def txs_different(tx1, tx2), do: Transaction.raw_txhash(tx1) != Transaction.raw_txhash(tx2)
end
