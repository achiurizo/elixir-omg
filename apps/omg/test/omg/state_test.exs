# Copyright 2018 OmiseGO Pte Ltd
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

defmodule OMG.StateTest do
  @moduledoc """
  Smoke tests the imperative shell - runs a happy path on `OMG.State`. Logic tested elsewhere
  """
  use ExUnitFixtures
  use ExUnit.Case, async: false

  use OMG.DB.Fixtures

  alias OMG.State
  alias OMG.TestHelper
  alias OMG.Utxo

  require Utxo

  @eth OMG.Eth.RootChain.eth_pseudo_address()

  deffixture standalone_state_server(db_initialized) do
    # match variables to hide "unused var" warnings (can't be fixed by underscoring in line above, breaks macro):
    _ = db_initialized
    # need to override that to very often, so that many checks fall in between a single child chain block submission
    {:ok, started_apps} = Application.ensure_all_started(:omg_db)

    on_exit(fn ->
      started_apps
      |> Enum.reverse()
      |> Enum.map(fn app -> :ok = Application.stop(app) end)
    end)

    # the pubsub is required, because `OMG.State` is broadcasting to the `OMG.InternalEventBus`
    {:ok, _} =
      Supervisor.start_link(
        [
          {OMG.State, []},
          {Phoenix.PubSub.PG2, [name: OMG.InternalEventBus]}
        ],
        strategy: :one_for_one,
        name: :sup
      )

    :ok
  end

  @tag fixtures: [:alice, :standalone_state_server]
  test "can execute various calls on OMG.State, one happy path only", %{alice: alice} do
    # deposits, transactions, utxo existence
    assert {:ok, _} = State.deposit([%{owner: alice.addr, currency: @eth, amount: 10, blknum: 1}])
    assert true == State.utxo_exists?(Utxo.position(1, 0, 0))
    assert {:ok, _} = State.exec(TestHelper.create_recovered([{1, 0, 0, alice}], @eth, [{alice, 3}]), :ignore)
    # block forming & status
    assert {blknum, _} = State.get_status()
    assert :ok = State.form_block()
    # exits, with invalid ones
    assert {:ok, _db, _} = State.exit_utxos([Utxo.position(blknum, 0, 0)])
    # close block
    assert {:ok, _db} = State.close_block(123)
  end

  @tag fixtures: [:alice, :standalone_state_server]
  test "TEMPORARY TEST: has no race condition between exiting and form_block", %{alice: alice} do
    # FIXME: there is a different test testing the same thing added in `state/persistence_test.exs`
    #        decide which is better and keep that, but only after this is green
    #        Then, fix test title(s)
    #        Notice, that this test uses `close_block` specifically, not sure if relevant
    # deposits, transactions, utxo existence
    assert {:ok, _} = State.deposit([%{owner: alice.addr, currency: @eth, amount: 10, blknum: 1}])
    # creates {1000, 0, 0} utxo
    assert {:ok, _} = State.exec(TestHelper.create_recovered([{1, 0, 0, alice}], @eth, [{alice, 3}]), :ignore)
    assert true == State.utxo_exists?(Utxo.position(1000, 0, 0))
    # exits it
    assert {:ok, _db, _} = State.exit_utxos([Utxo.position(1000, 0, 0)])
    assert false == State.utxo_exists?(Utxo.position(1000, 0, 0))

    # forming block will use `pending_txs`, which contain the one creating {1000, 0, 0}, it will pop back up after restart :(
    assert {:ok, db_updates} = State.close_block(123)
    OMG.DB.multi_update(db_updates)

    :ok = Supervisor.terminate_child(:sup, OMG.State)
    {:ok, _} = Supervisor.restart_child(:sup, OMG.State)

    assert false == State.utxo_exists?(Utxo.position(1000, 0, 0))
  end
end
