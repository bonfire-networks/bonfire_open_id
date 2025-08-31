defmodule Bonfire.OpenID.Web.Plugs.PKCEFix do
  @moduledoc """
  Minimal fix for PKCE authentication with public clients.
  
  Boruta has a bug where `should_check_secret?` checks for grant_type "code" 
  instead of "authorization_code", causing public clients with PKCE to fail.
  
  This plug detects PKCE requests and injects the client's secret to satisfy
  Boruta's authentication requirement, while PKCE provides the actual security.
  """
  
  use Bonfire.UI.Common.Web, :plug
  alias Boruta.ClientsAdapter
  
  def init(opts), do: opts
  
  def call(%Plug.Conn{method: "POST", request_path: "/oauth/token"} = conn, _opts) do
    maybe_fix_pkce_auth(conn)
  end
  
  def call(conn, _opts), do: conn
  
  defp maybe_fix_pkce_auth(conn) do
    case conn.body_params do
      %{"grant_type" => "authorization_code", "code_verifier" => _verifier, "client_id" => client_id} ->
        inject_secret_for_public_client(conn, client_id)
      _ ->
        conn
    end
  end
  
  defp inject_secret_for_public_client(conn, client_id) do
    case ClientsAdapter.get_client(client_id) do
      %Boruta.Oauth.Client{confidential: false, secret: secret} ->
        # This is a public client - inject its secret to work around Boruta's bug
        debug("Injecting secret for public PKCE client")
        updated_body_params = Map.put(conn.body_params, "client_secret", secret)
        updated_params = Map.put(conn.params, "client_secret", secret)
        
        %{conn | 
          body_params: updated_body_params,
          params: updated_params
        }
      _ ->
        # Not a public client or client not found - let Boruta handle normally
        conn
    end
  end
end