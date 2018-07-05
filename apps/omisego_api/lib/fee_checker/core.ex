defmodule OmiseGO.API.FeeChecker.Core do
  @moduledoc """
  Transaction's fee validation functions
  """

  alias OmiseGO.API.Crypto
  alias OmiseGO.API.State.Transaction
  alias OmiseGO.API.State.Transaction.Recovered

  @type fee_spec_t() :: %{token: Crypto.address_t(), flat_fee: non_neg_integer}
  @type token_fee_t() :: %{Crypto.address_t() => non_neg_integer}

  @doc """
  Calculates fee from tx and checks whether token is allowed and both percentage and flat fee limits are met
  """
  @spec transaction_fees(Recovered.t(), list(fee_spec_t())) :: {:ok, token_fee_t()} | {:error, :token_not_allowed}
  def transaction_fees(recovered_tx, token_fees) do
    %Recovered{raw_tx: %Transaction{amount1: amount1, amount2: amount2, cur12: currency}} = recovered_tx

    with {:ok, fee} <- get_fee_for_token(token_fees, currency) do
      {:ok, %{currency => amount1 + amount2 + fee}}
    end
  end

  @spec get_fee_for_token(list(fee_spec_t()), Crypto.address_t()) ::
          {:ok, non_neg_integer} | {:error, :token_not_allowed}
  defp get_fee_for_token(token_fees, currency) do
    token_fees
    |> Enum.find(fn %{token: token} -> token == currency end)
    |> extract_fee()
  end

  defp extract_fee(%{token: _, flat_fee: flat_fee}), do: {:ok, flat_fee}
  defp extract_fee(nil), do: {:error, :token_not_allowed}

  def parse_fee_specs(json) do
    fee_specs = json |> Enum.map(&parse_fee_spec/1)

    errors =
      fee_specs
      |> Enum.with_index(1)
      |> Enum.filter(&match?({{:error, _}, _index}, &1))

    {errors, fee_specs}
  end

  defp parse_fee_spec(%{"flat_fee" => fee, "token" => token}) do
    # defensive code against user input
    with {:ok, fee} <- validate_fee(fee),
         {:ok, addr} <- validate_token(token) do
      %{token: addr, flat_fee: fee}
    end
  end

  defp parse_fee_spec(_), do: {:error, :invalid_fee_spec}

  defp validate_fee(fee) when is_integer(fee) and fee >= 0, do: {:ok, fee}
  defp validate_fee(_fee), do: {:error, :invalid_fee}

  defp validate_token(token) do
    case is_binary(token) && parse_token_address(token) do
      {:ok, addr} when byte_size(addr) == 20 ->
        {:ok, addr}

      _ ->
        {:error, :invalid_token}
    end
  end

  defp parse_token_address(token), do: token |> String.trim_leading("0x") |> String.upcase() |> Base.decode16()
end
