defmodule OmiseGOWatcherWeb.Controller.Utxo do
  @moduledoc """
  Operations related to utxo.
  Modify the state in the database.
  """
  alias OmiseGOWatcher.{Repo, UtxoDB}
  alias OmiseGO.JSONRPC
  use OmiseGOWatcherWeb, :controller
  import Ecto.Query, only: [from: 2]

  def available(conn, %{"address" => address}) do
    address_decode = JSONRPC.Client.decode(:bitstring, address)
    utxos = Repo.all(from(tr in UtxoDB, where: tr.address == ^address_decode, select: tr))
    fields_names = List.delete(UtxoDB.field_names(), :address)

    json(conn, %{
      address: address,
      utxos: JSONRPC.Client.encode(Enum.map(utxos, &Map.take(&1, fields_names)))
    })
  end
end
