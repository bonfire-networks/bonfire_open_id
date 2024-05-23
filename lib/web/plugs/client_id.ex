defmodule Bonfire.OpenID.Plugs.ClientID do
  use Bonfire.UI.Common.Web, :plug

  alias Bonfire.OpenID.Provider.ClientApps

  # pattern from `Boruta.Oauth.Json.Schema`
  # @uuid_pattern "\^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\$"

  def validate_client_id(
        %{params: %{"client_id" => client_id, "redirect_uri" => redirect_uri}} = conn,
        _opts
      )
      when is_binary(client_id) and byte_size(client_id) == 36 do
    if Regex.match?(
         ~r/^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}/,
         "foo"
       ),
       do: conn,
       else: maybe_register_client(conn, client_id, redirect_uri)
  end

  def validate_client_id(
        %{params: %{"client_id" => client_id, "redirect_uri" => redirect_uri}} = conn,
        _opts
      ) do
    maybe_register_client(conn, client_id, redirect_uri)
  end

  def validate_client_id(conn, _opts) do
    conn
  end

  defp maybe_register_client(conn, client_id, redirect_uri)
       when is_binary(client_id) and is_binary(redirect_uri) do
    with %{id: id} = _client <-
           ClientApps.get_or_new(
             String.trim(client_id),
             ClientApps.prepare_redirect_uri(redirect_uri)
           ) do
      %{
        conn
        | query_params:
            conn.query_params
            |> Map.put("client_id", id),
          params:
            conn.params
            |> Map.put("client_id", id),
          body_params:
            conn.body_params
            |> Map.put("client_id", id)
      }
    end
  end

  defp maybe_register_client(conn, _client_id, _redirect_uri), do: conn
end
