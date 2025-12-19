defmodule Bonfire.OpenID.Web.ClientController do
  use Bonfire.UI.Common.Web, :controller

  # import Bonfire.OpenID
  alias Bonfire.OpenID.Client

  # The `Authentication` module here is an imaginary interface for setting session state
  def create(conn, %{"provider" => provider} = params) do
    params = Map.drop(params, ["provider"])

    with provider when not is_nil(provider) <- maybe_to_atom(provider) |> flood("provider") do
      if provider_config = ed(Client.open_id_connect_providers(), provider, nil) do
        #  redirect to authorization URL
        if params == %{} do
          # start flow: redirect to remote authorization URL
          case openid_provider_url(provider, provider_config) do
            {:ok, url} when is_binary(url) ->
              redirect_to(conn, url, type: :maybe_external)

            other ->
              error(other, "OpenID redirect URL could not be generated for provider: #{provider}")
              flood(provider_config, "provider")

              raise Bonfire.Fail, {:not_found, "Provider could not be reached"}
          end
        else
          # error or callback after coming back from remote 
          process_and_maybe_raise_error(
            conn,
            params,
            l("An error occurred when trying to sign in with OpenID"),
            false
          ) || with_open_id_connect(conn, provider, Map.new(provider_config), params)
        end
      else
        if provider_config = ed(Client.oauth2_providers(), provider, nil) do
          debug(provider_config)
          # start flow: redirect to remote authorization URL
          if params == %{} do
            redirect_to(conn, oauth_provider_url(provider, provider_config),
              type: :maybe_external
            )
          else
            # error or callback after coming back from remote 
            process_and_maybe_raise_error(
              conn,
              params,
              l("An error occurred when trying to sign in with OAuth2"),
              false
            ) || with_oauth2(conn, provider, Map.new(provider_config), params)
          end
        else
          raise Bonfire.Fail, {:not_found, "Provider #{inspect(provider)}"}
        end
      end
    else
      other ->
        error(other, "Provider not found")

        raise Bonfire.Fail, {:not_found, "Provider #{inspect(provider)}"}
    end
  end

  def oauth_provider_url(provider, config \\ nil) do
    with config when not is_nil(config) <- config || ed(Client.oauth2_providers(), provider, nil) do
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
    else
      _ ->
        flood(
          Client.oauth2_providers(),
          "OAuth2 provider config not found for #{inspect(provider)}"
        )

        raise Bonfire.Fail, {:not_found, "OAuth2 provider not found"}
    end
  end

  def openid_callback_url(provider) do
    "#{Bonfire.Common.URIs.base_url()}/openid/client/#{provider}"
  end

  def openid_provider_url(provider, provider_config \\ nil) do
    with provider_config when not is_nil(provider_config) <-
           provider_config || ed(Client.open_id_connect_providers(), provider, nil) do
      # Base parameters
      base_params = %{
        "state" => Bonfire.Common.Text.random_string(),
        "nonce" => Bonfire.Common.Text.random_string()
      }

      # Add PKCE parameters if present in config
      additional_params =
        case provider_config do
          %{pkce: true, code_challenge: code_challenge, code_challenge_method: method} ->
            Map.merge(base_params, %{
              "code_challenge" => code_challenge,
              "code_challenge_method" => method
            })

          _ ->
            base_params
        end

      provider_config
      |> OpenIDConnect.authorization_uri(openid_callback_url(provider), additional_params)
    else
      _ ->
        flood(
          Client.open_id_connect_providers(),
          "OpenID provider config not found for #{inspect(provider)}"
        )

        raise Bonfire.Fail, {:not_found, "OpenID provider not found"}
    end
  end

  defp user_info_body(userinfo_uri, access_token) do
    if userinfo_uri do
      Bonfire.Common.HTTP.get(userinfo_uri, [{"authorization", "Bearer #{access_token}"}])
    else
      {:ok, %{body: "{}"}}
    end
  end

  defp with_oauth2(
         conn,
         provider,
         %{
           client_id: client_id,
           access_token_uri: access_token_uri,
           client_secret: client_secret,
           redirect_uri: redirect_uri
         } = config,
         %{"code" => code} = _params
       ) do
    debug(code, "Received OAuth code at #{DateTime.utc_now()}")

    query =
      URI.encode_query(%{
        grant_type: config[:grant_type] || "authorization_code",
        code: code,
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        scope: config[:scope]
      })

    with {:ok, %{body: token_result}} <-
           Bonfire.Common.HTTP.post(
             access_token_uri,
             query,
             [
               {"content-type", "application/x-www-form-urlencoded"},
               {"accept", "application/json"}
             ]
           )
           |> debug("token_result"),
         #  Bonfire.Common.HTTP.post("#{access_token_uri}?#{query}", ""),
         %{"access_token" => access_token} = token_data <-
           (case Jason.decode(token_result) do
              {:ok, data} -> data
              _ -> URI.decode_query(token_result)
            end)
           |> debug("token_data"),
         {:ok, %{body: userinfo_body}} <- user_info_body(config[:userinfo_uri], access_token),
         {:ok, userinfo} <- Jason.decode(userinfo_body) do
      process_external_auth(conn, provider, config, Enum.into(userinfo, token_data))
    else
      %{"error_description" => msg} = e ->
        error(e)
        raise Bonfire.Fail, {:unknown, msg}

      %{"error" => msg} = e when is_binary(msg) ->
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
      process_external_auth(conn, provider, provider_config, Enum.into(claims, tokens))
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
      {:ok, body} ->
        process_and_maybe_raise_error(conn, body, error_msg)

      _ ->
        process_and_maybe_raise_error(conn, body, error_msg)
    end
  end

  defp process_body_error(conn, {_, body}, error_msg) do
    process_and_maybe_raise_error(conn, body, error_msg)
  end

  defp process_body_error(conn, body, error_msg) do
    process_and_maybe_raise_error(conn, body, error_msg)
  end

  defp process_and_maybe_raise_error(conn, data_or_params, error_msg, force? \\ true)

  defp process_and_maybe_raise_error(conn, %{} = data_or_params, error_msg, force?) do
    case data_or_params do
      %{"error_description" => e} = data_or_params ->
        raise_error(conn, data_or_params, e || error_msg)

      %{"error" => e} = body ->
        raise_error(conn, data_or_params, e || error_msg)

      _ ->
        if force?, do: raise_error(conn, data_or_params, error_msg), else: false
    end
  end

  defp process_and_maybe_raise_error(conn, data_or_params, error_msg, force?) do
    if force?, do: raise_error(conn, data_or_params, error_msg), else: false
  end

  defp raise_error(_conn, body, error_msg) do
    error(body, error_msg)

    raise Bonfire.Fail, {:unknown, error_msg}
  end

  defp process_external_auth(conn, provider, provider_config, params) do
    # debug(conn)

    if current_user = current_user(conn) do
      info(params, "params")

      with {:ok, _obj} <-
             Client.link_provider_alias(current_user, provider, provider_config, params) do
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
                 Client.user_external_url(params, provider_config)
                 ~> maybe_apply(Bonfire.Social.Graph.Aliases, :all_subjects_by_object, [
                   {:provider, provider, ..., params}
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
