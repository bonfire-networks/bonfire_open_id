defmodule Bonfire.OpenID.Web.ClientController do
  use Bonfire.UI.Common.Web, :controller

  import Bonfire.OpenID.Integration

  # The `Authentication` module here is an imaginary interface for setting session state
  def create(conn, %{"provider" => provider} = params) do
    with provider when is_atom(provider) <- maybe_to_atom(provider),
         {:ok, tokens} <- OpenIDConnect.fetch_tokens(provider, params["code"]),
         {:ok, claims} <- OpenIDConnect.verify(provider, tokens["id_token"]) do
      attempt_login_or_create(conn, claims)
    else
      other ->
        error(other)

        send_resp(conn, 401, "An error occurred with OpenID Connect.")
    end
  end

  def attempt_login_or_create(conn, params) do
    params = %{openid_email: params["email"]}

    with %{openid_email: email} when is_binary(email) <- params,
         # TODO: should check that this user has previously authenticated with this provider
         {:ok, conn} <- Bonfire.UI.Me.LoginController.attempt(conn, params) do
      conn
    else
      nil ->
        send_resp(
          conn,
          401,
          "The oauth provider did not indicate an email for your account. This is not currently supported."
        )

      other ->
        debug(other, "Could not login, attempt creating an account")

        with {:ok, conn} <-
               Bonfire.UI.Me.SignupController.attempt(conn, params)
               |> debug("attempted creating an account") do
          conn
        else
          other ->
            error(other)

            send_resp(conn, 401, "Could not find or create an account for you, sorry.")
        end
    end
  end
end
