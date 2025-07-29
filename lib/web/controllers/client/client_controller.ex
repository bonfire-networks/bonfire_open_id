defmodule Bonfire.OpenID.Web.ClientController do
  use Bonfire.UI.Common.Web, :controller

  # import Bonfire.OpenID
  alias Bonfire.OpenID.Client

  # The `Authentication` module here is an imaginary interface for setting session state
  def create(conn, %{"provider" => provider} = params) do
    params = Map.drop(params, ["provider"])

    with provider when is_atom(provider) <- maybe_to_atom(provider) do
      if provider_config = Client.open_id_connect_providers()[provider] do
        #  redirect to authorization URL
        if params == %{} do
          # start flow: redirect to remote authorization URL
          redirect_to(conn, openid_provider_url(provider, provider_config), type: :maybe_external)
        else
          # callback after coming back from remote 
          with_open_id_connect(conn, provider, Map.new(provider_config), params)
        end
      else
        if provider_config = Client.oauth2_providers()[provider] do
          debug(provider_config)
          # start flow: redirect to remote authorization URL
          if params == %{} do
            redirect_to(conn, oauth_provider_url(provider, provider_config),
              type: :maybe_external
            )
          else
            # callback after coming back from remote 
            with_oauth2(conn, provider, Map.new(provider_config), params)
          end
        else
          raise Bonfire.Fail, {:not_found, "Provider #{inspect(provider)}"}
        end
      end
    else
      other ->
        error(other)

        raise Bonfire.Fail, {:not_found, "Provider #{inspect(provider)}"}
    end
  end

  def oauth_provider_url(provider, config \\ nil) do
    config = config || Client.oauth2_providers()[provider]

    params =
      %{
        # Required - indicates we want an authorization code
        "response_type" => config[:response_type] || "code",
        # Required - the client's ID
        "client_id" => config[:client_id],
        # "http://localhost:4001/openid_client/test_provider", # Required - must match registered URI
        "redirect_uri" => config[:redirect_uri],
        # Optional - space-separated list of requested permissions
        "scope" => config[:scope],
        # Recommended - random string to prevent CSRF
        "state" => Bonfire.Common.Text.random_string()
        # "prompt" => "consent"            # Optional - force showing the consent screen
        # "code_challenge_method" => "S256" # Optional - PKCE hash method
        # "code_challenge" => ?, # Optional - for PKCE
      }
      |> URI.encode_query()

    "#{config[:authorize_uri]}?#{params}"
  end

  def openid_callback_url(provider) do
    "#{Bonfire.Common.URIs.base_url()}/openid/client/#{provider}"
  end

  def openid_provider_url(provider, config \\ nil) do
    Utils.ok_unwrap(
      Map.new(config || Client.open_id_connect_providers()[provider])
      |> OpenIDConnect.authorization_uri(openid_callback_url(provider), %{
        "state" => Bonfire.Common.Text.random_string(),
        "nonce" => Bonfire.Common.Text.random_string()
      })
    )
  end

  defp with_oauth2(
         conn,
         provider,
         %{
           client_id: client_id,
           access_token_uri: access_token_uri,
           client_secret: client_secret,
           redirect_uri: redirect_uri,
           userinfo_uri: userinfo_uri
         },
         %{"code" => code} = _params
       ) do
    query =
      URI.encode_query(%{
        code: code,
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri
      })

    with {:ok, %{body: token_result}} <-
           Bonfire.Common.HTTP.post("#{access_token_uri}?#{query}", ""),
         %{"access_token" => access_token} = token_data <-
           URI.decode_query(token_result) |> debug("token_data"),
         {:ok, %{body: userinfo_body}} <-
           Bonfire.Common.HTTP.get(userinfo_uri, [{"authorization", "Bearer #{access_token}"}]),
         {:ok, userinfo} <- Jason.decode(userinfo_body) do
      process_external_auth(conn, provider, Enum.into(userinfo, token_data))
    else
      %{"error_description" => msg} = e ->
        error(e)
        raise Bonfire.Fail, {:unknown, msg}

      e ->
        error(e)
        raise Bonfire.Fail, {:unknown, l("There was an error.")}
    end
  end

  defp with_oauth2(
         conn,
         _provider,
         %{client_id: client_id, authorize_uri: authorize_uri, redirect_uri: redirect_uri},
         _params
       ) do
    query =
      URI.encode_query(%{
        client_id: client_id,
        state: Text.random_string(),
        redirect_uri: redirect_uri
      })

    redirect_to(conn, debug("#{authorize_uri}?#{query}"), type: :maybe_external)
  end

  defp with_open_id_connect(conn, provider, provider_config, params) do
    info(params, "uri_params")

    # provider_config = provider_config
    # |> Map.put(:redirect_uri, "#{Bonfire.Common.URIs.base_url()}/openid/client/#{provider}")

    error_msg = l("An unknown error occurred with OpenID Connect.")
    # Map.merge(params, %{"scope"=> "openid /read-public"})
    with {:ok, tokens} <-
           OpenIDConnect.fetch_tokens(
             provider_config,
             Enums.input_to_atoms(params)
             |> Map.put(:redirect_uri, openid_callback_url(provider))
             |> info("prepared_params")
           )
           |> info("fetched_tokens"),
         {:ok, claims} <-
           OpenIDConnect.verify(provider_config, tokens["id_token"]) |> info("verified_claims") do
      process_external_auth(conn, provider, Enum.into(claims, tokens))
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
        process_body_error(conn, body, e || error_msg)

      {:ok, %{"error" => e} = body} ->
        process_body_error(conn, body, e || error_msg)

      {:ok, _} = body ->
        process_body_error(conn, body, error_msg)

      _ ->
        process_body_error(conn, body, error_msg)
    end
  end

  defp process_body_error(conn, {_, body}, error_msg) do
    process_body_error(conn, body, error_msg)
  end

  defp process_body_error(conn, body, error_msg) do
    error(body, error_msg)

    raise Bonfire.Fail, {:unknown, error_msg}
  end

  defp process_external_auth(conn, provider, params) do
    # debug(conn)

    if current_user = current_user(conn) do
      info(params, "params")

      with {:ok, _obj} <- Client.link_provider_alias(current_user, provider, params) do
        redirect_to(conn, "/user")
      else
        e ->
          msg = l("An error occurred saving the external authentication.")
          error(e, msg)
          raise Bonfire.Fail, {:unknown, msg}
      end
    else
      email = params["email"]

      with true <- is_binary(email),
           # TODO: should check that this user has previously authenticated with this provider?
           {:ok, conn} <- Bonfire.UI.Me.LoginController.attempt(conn, %{openid_email: email}) do
        conn
      else
        false ->
          with [%{account: _} = user] <-
                 maybe_apply(Bonfire.Social.Graph.Aliases, :all_subjects_by_object, [
                   {:provider, provider, params}
                 ]) do
            user = repo().maybe_preload(user, :account)
            info(user, "found user")
            Bonfire.UI.Me.LoginController.logged_in(user.account, user, conn)
          else
            [] ->
              handle_unknown_account_with_no_email(conn, provider, params)

            {:error, :not_found} ->
              handle_unknown_account_with_no_email(conn, provider, params)

            {:error, e} when is_binary(e) ->
              error(
                e,
                "cannot register new account with no email, and error occurred while trying to find existing account"
              )

              raise Bonfire.Fail, {:invalid_credentials, e}

            e ->
              error(
                e,
                "cannot register new account with no email, and error occurred while trying to find existing account"
              )

              raise Bonfire.Fail, :invalid_credentials
          end

        other ->
          info(other, "Could not login, attempt creating an account")

          # TODO: make this configurable per-provider
          with {:ok, conn} <-
                 Bonfire.UI.Me.SignupController.attempt(conn, %{openid_email: email}, %{},
                   must_confirm?: false
                 )
                 |> info("attempted creating an account") do
            conn
          else
            other ->
              error(other)

              raise Bonfire.Fail,
                    {:invalid_credentials,
                     l("Could not find or create an account for you, sorry.")}
          end
      end
    end

    # rescue
    #   exception ->
    #     error(exception, "Exception during SSO attempt")

    #     send_resp(
    #       conn,
    #       401,
    #       l(
    #         "An unexpected error occurred while trying to find or create an account for you, please contact the instance admins."
    #       )
    #     )
  end

  defp handle_unknown_account_with_no_email(conn, provider, params) do
    debug(params, "no existing account found, and no email provided")

    # WIP: support sign up with openid/oauth providers who don't provide the user's email address, we need to have a form to request for an email address (and maybe optionally a PW too) so we can create an account for them and then link it to the provider token (we can skip email confirmation)

    cache_key = token_put_cache(provider, params)

    conn
    |> assign(
      :open_id_provider,
      {provider, cache_key}
    )
    |> Plug.Conn.put_session(:open_id_provider, {provider, cache_key})
    |> Bonfire.UI.Me.SignupController.render_view()

    # raise Bonfire.Fail,
    #       {:invalid_credentials,
    #        l(
    #          "The SSO provider did not indicate an email for your account, which is not currently supported unless you first sign in to your Bonfire account and then add it in your profile settings."
    #        )}
  end

  # 30 minutes
  @token_ttl 30 * 60 * 1000

  def token_put_cache(provider, data) do
    key = "openid_provider:#{provider}:#{Bonfire.Common.Text.random_string()}"
    Bonfire.Common.Cache.put(key, data, expire: @token_ttl)

    key
  end
end
