defmodule Bonfire.OpenID.OAuthRefreshDanceTest do
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

  test "can refresh OAuth tokens",
       %{
         client: client,
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         secondary_instance: secondary_instance,
         access_token_uri: access_token_uri
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

    # Step 2: Use refresh token to get new access token
    req = create_req_client(secondary_instance)

    refresh_params = %{
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: client.id,
      client_secret: client.secret
      # Note: scope is optional in refresh token requests
    }

    {:ok, refresh_response} =
      apply_with_repo_sync(fn ->
        Req.post(req,
          url: access_token_uri,
          form: refresh_params
        )
      end)

    # Verify we get new tokens
    assert %{"access_token" => new_access_token} = refresh_response.body
    assert new_access_token, "Should receive new access token"

    assert new_access_token != access_token,
           "New access token should be different from original"

    # Check if we get a new refresh token (some systems rotate refresh tokens)
    new_refresh_token = refresh_response.body["refresh_token"]

    if new_refresh_token do
      debug("Server rotated refresh token")

      assert new_refresh_token != refresh_token,
             "New refresh token should be different if rotated"
    else
      debug("Server kept same refresh token")
    end

    # Verify new access token works
    verify_userinfo_endpoint(secondary_instance, new_access_token)

    # Optional: Verify old access token is revoked (depending on server behavior)
    # Some servers revoke old tokens, others keep them valid until expiry
    # verify_token_revoked_or_valid(main_instance, access_token)
  end
end
