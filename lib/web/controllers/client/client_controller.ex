defmodule Bonfire.OpenID.Web.ClientController do
  use Bonfire.UI.Common.Web, :controller

  import Bonfire.OpenID
  alias Bonfire.OpenID.Client

  # The `Authentication` module here is an imaginary interface for setting session state
  def create(conn, %{"provider" => provider} = params) do
    with provider when is_atom(provider) <- maybe_to_atom(provider) do
      if provider_config = Client.open_id_connect_providers()[provider] do
        with_open_id_connect(conn, provider, Map.new(provider_config), params)
      else
        if oauth2 = Client.oauth2_providers()[provider] do
          debug(oauth2)
          with_oauth2(conn, Map.new(oauth2), params)
        else
          send_resp(conn, 401, "Provider not recognised.")
        end
      end
    else
      other ->
        error(other)

        send_resp(conn, 401, "Provider not recognised.")
    end
  end

  defp with_oauth2(
         conn,
         %{
           client_id: client_id,
           access_token_uri: access_token_uri,
           client_secret: client_secret,
           redirect_uri: redirect_uri
         },
         %{"code" => code} = params
       ) do
    debug(params, "TODO")

    query =
      URI.encode_query(%{
        code: code,
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri
      })

    with {:ok, %{body: result}} <- Bonfire.Common.HTTP.post("#{access_token_uri}?#{query}", ""),
         %{"access_token" => access_token} = result <- URI.decode_query(result) do
      result
      |> debug("TODO")

      send_resp(conn, 401, "OK - TODO")
    else
      %{"error_description" => msg} = e ->
        error(e)
        send_resp(conn, 401, msg)

      e ->
        error(e)
        send_resp(conn, 401, l("There was an error."))
    end
  end

  defp with_oauth2(
         conn,
         %{client_id: client_id, authorize_uri: authorize_uri, redirect_uri: redirect_uri},
         _params
       ) do
    query =
      URI.encode_query(%{
        client_id: client_id,
        state: Text.random_string(),
        redirect_uri: redirect_uri
      })

    redirect_to(conn, "#{authorize_uri}?#{query}")
  end

  defp with_open_id_connect(conn, provider, provider_config, params) do
    debug(params)
    error_msg = l("An unknown error occurred with OpenID Connect.")
    # Map.merge(params, %{"scope"=> "openid /read-public"})
    with {:ok, tokens} <- OpenIDConnect.fetch_tokens(provider_config, params),
         {:ok, claims} <- OpenIDConnect.verify(provider_config, tokens["id_token"]) do
      process_open_id_connect(conn, provider, Enum.into(claims, tokens))
    else
      {:error, :fetch_tokens, %{body: "{" <> _ = body}} ->
        process_body_error(conn, body, error_msg)

      {_, body} ->
        process_body_error(conn, body, error_msg)

      other ->
        process_body_error(conn, other, error_msg)
    end
  end

  defp process_body_error(conn, body, error_msg) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, %{"error_description" => e} = body} ->
        error(body, error_msg)
        send_resp(conn, 401, e)

      {:ok, %{"error" => e} = body} ->
        error(body, error_msg)
        send_resp(conn, 401, e)

      {:ok, _} = body ->
        error(body, error_msg)
        send_resp(conn, 401, error_msg)

      _ ->
        error(body, error_msg)

        send_resp(conn, 401, error_msg)
    end
  end

  defp process_body_error(conn, {_, body}, error_msg) do
    process_body_error(conn, body, error_msg)
  end

  defp process_body_error(conn, body, error_msg) do
    error(body, error_msg)

    send_resp(conn, 401, error_msg)
  end

  defp process_open_id_connect(conn, provider, params) do
    debug(conn)

    if current_user = current_user(conn) do
      debug(params)

      with {:ok, _obj} <-
             maybe_apply(Bonfire.Social.Graph.Aliases, :add, [
               current_user,
               {:provider, provider, params},
               update_existing: true
             ]) do
        redirect_to(conn, "/user")
      else
        e ->
          msg = l("An error occurred saving the external authentication.")
          error(e, msg)
          send_resp(conn, 401, msg)
      end
    else
      email = params["email"]

      with true <- is_binary(email),
           # TODO: should check that this user has previously authenticated with this provider
           {:ok, conn} <- Bonfire.UI.Me.LoginController.attempt(conn, %{openid_email: email}) do
        conn
      else
        false ->
          with [%{account: _} = user] <-
                 maybe_apply(Bonfire.Social.Graph.Aliases, :all_subjects_by_object, [
                   {:provider, provider, params}
                 ]) do
            user = repo().maybe_preload(user, :account)
            debug(user)
            Bonfire.UI.Me.LoginController.logged_in(user.account, user, conn)
          else
            e ->
              error(e, "could not auth with no email")

              send_resp(
                conn,
                401,
                l(
                  "The oauth provider did not indicate an email for your account, which is not currently supported unless you first sign in to your Bonfire account and then add it in your profile settings. "
                )
              )
          end

        other ->
          debug(other, "Could not login, attempt creating an account")

          with {:ok, conn} <-
                 Bonfire.UI.Me.SignupController.attempt(conn, %{openid_email: email})
                 |> debug("attempted creating an account") do
            conn
          else
            other ->
              error(other)

              send_resp(conn, 401, l("Could not find or create an account for you, sorry."))
          end
      end
    end
  end
end
