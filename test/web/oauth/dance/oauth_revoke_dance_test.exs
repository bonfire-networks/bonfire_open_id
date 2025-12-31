defmodule Bonfire.OpenID.OAuthRevokeDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []
  import Bonfire.OpenID.DanceCase
  import Bonfire.OpenID.OAuthDance

  @moduletag :test_instance

  use Arrows
  import Untangle
  import Bonfire.Common.Config, only: [repo: 0]
  use Bonfire.Common.E
  use Bonfire.Common.Config
  alias Bonfire.Common.Utils
  alias Bonfire.Common.TestInstanceRepo
  alias Bonfire.OpenID.Provider.ClientApps

  setup do
    return = setup()

    on_exit(fn ->
      teardown(return.client)
    end)

    return
  end

  test "can revoke OAuth tokens",
       %{
         client: client,
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         secondary_instance: secondary_instance
       } = context do
    # Step 1: Get initial tokens using authorization code flow
    {access_token, refresh_token} =
      get_initial_tokens_with_refresh(
        client,
        redirect_uri,
        main_instance,
        secondary_instance,
        context
      )

    # Verify initial access token works
    verify_userinfo_endpoint(secondary_instance, access_token)

    # Step 2: Revoke the access token
    revoke_uri = "#{secondary_instance}/oauth/revoke"
    req = create_req_client(secondary_instance)

    revoke_params = %{
      token: access_token,
      # Optional hint to help server process faster
      token_type_hint: "access_token",
      client_id: client.id,
      client_secret: client.secret
    }

    {:ok, revoke_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: revoke_uri,
          form: revoke_params
        )
      end)

    # RFC 7009: Revocation endpoint should return 200 even for invalid tokens
    assert revoke_response.status == 200, "Revocation should return 200 OK"

    # Step 3: Verify access token is now invalid
    verify_token_revoked(secondary_instance, access_token)

    # Step 4: Test revoking refresh token
    if refresh_token do
      refresh_revoke_params = %{
        token: refresh_token,
        token_type_hint: "refresh_token",
        client_id: client.id,
        client_secret: client.secret
      }

      {:ok, refresh_revoke_response} =
        apply_with_repo_sync(fn ->
          Req.post(req,
            url: revoke_uri,
            form: refresh_revoke_params
          )
        end)

      assert refresh_revoke_response.status == 200,
             "Refresh token revocation should return 200 OK"

      # Verify refresh token is now invalid (try to use it)
      verify_refresh_token_revoked(secondary_instance, refresh_token, client)
    end
  end
end
