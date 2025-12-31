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
    return = setup()

    on_exit(fn ->
      teardown(return.client)
    end)

    return
  end

  test "can login using OAuth with authorization code flow",
       %{
         client: client,
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         secondary_instance: secondary_instance,
         access_token_uri: access_token_uri
       } = context do
    # Get tokens using DRY helper
    auth_url =
      get_auth_url(client.name)
      |> flood("Auth URL")

    req = create_req_client(main_instance)
    login_response = perform_login_flow(req, auth_url, context)

    query_params = extract_query_params(login_response)
    auth_code = query_params["code"]
    assert auth_code, "Should receive authorization code"

    req = create_req_client(secondary_instance)
    # Use DRY helper for token exchange
    token_data =
      exchange_code_for_tokens(req, access_token_uri, client, auth_code, redirect_uri)

    assert %{"access_token" => access_token} = token_data
    assert access_token, "Should receive access token"

    # Verify access token works
    verify_userinfo_endpoint(secondary_instance, access_token)
  end
end
