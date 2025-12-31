defmodule Bonfire.OpenID.OAuthImplicitDanceTest do
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

  test "can login using OAuth with implicit flow",
       %{
         client: client,
         redirect_uri: redirect_uri,
         main_instance: main_instance,
         secondary_instance: secondary_instance
       } = context do
    {_authorize_uri, _access_token_uri} =
      setup_oauth_provider(client, secondary_instance,
        response_type: "token",
        scope: "identity data:public"
      )

    # Rest of test unchanged...
    auth_url = get_auth_url(client.name)
    req = create_req_client(main_instance)
    login_response = perform_login_flow(req, auth_url, context)

    fragment_params =
      extract_fragment_params(login_response)
      |> flood("fragment_params")

    access_token = fragment_params["access_token"]
    assert access_token, "Should receive access token in redirect fragment"

    verify_userinfo_endpoint(secondary_instance, access_token)
  end
end
