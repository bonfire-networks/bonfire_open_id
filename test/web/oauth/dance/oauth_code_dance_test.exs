defmodule Bonfire.OpenID.OAuthCodeDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []
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
    setup()
  end

  test "can login using OAuth with authorization code flow",
       %{client: client, redirect_uri: redirect_uri, main_instance: main_instance} = context do
    TestInstanceRepo.apply(fn ->
      assert Boruta.Config.repo() == TestInstanceRepo

      # Use DRY helper
      {_authorize_uri, access_token_uri} = setup_oauth_provider(client, main_instance)

      # Get tokens using DRY helper
      auth_url = get_auth_url(client.name)
      req = create_req_client(main_instance)
      login_response = perform_login_flow(req, auth_url, context)

      query_params = extract_query_params(login_response)
      auth_code = query_params["code"]
      assert auth_code, "Should receive authorization code"

      # Use DRY helper for token exchange
      token_data =
        exchange_code_for_tokens(req, access_token_uri, client, auth_code, redirect_uri)

      assert %{"access_token" => access_token} = token_data
      assert access_token, "Should receive access token"

      # Verify access token works
      verify_userinfo_endpoint(main_instance, access_token)
    end)
  end
end
