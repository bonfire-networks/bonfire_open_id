defmodule Bonfire.OpenID.OIDCAuthCodeDanceTest do
  use Bonfire.OpenID.DanceCase, async: false
  use Patch, only: []
  import Bonfire.OpenID.OIDCDance

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
    context = setup()
    on_exit(fn -> teardown(context.client) end)
    context
  end

  test "can login using OpenID Connect with authorization code flow + fetch cross-instance user info",
       context do
    test_oidc_flow(context, %{
      response_type: "code",
      scope: "openid profile email identity data:public",
      flow_type: :authorization_code,
      test_cross_instance: true
    })
  end

  # A reload, a back-then-forward, or a prefetch all request the sign-in callback a second time with the same code. Codes are single-use, so the provider answers `invalid_grant`, and that must land somewhere sensible rather than on an error page.
  test "replaying a spent sign-in callback redirects instead of erroring", context do
    req = create_req_client(context.main_instance)
    callback = sign_in_callback(req, context)
    code = extract_query_params(callback)["code"]

    # spend the code directly at the provider, which never runs our client, so this does not depend on the client being able to verify the ID token
    {:ok, spent} =
      exchange_code_for_tokens(
        context.discovery_document_uri,
        create_req_client(context.secondary_instance),
        context.client,
        code,
        context.redirect_uri
      )

    # the code was valid and is now spent, so the visit below is a genuine replay
    assert spent.status == 200
    assert spent.body["access_token"]

    {:ok, replay} = apply_with_repo_sync(fn -> Req.get(req, url: callback, redirect: false) end)
    refute replay.status >= 500
    assert replay.status in [302, 303]
  end

  # The whole client round trip: code exchange, ID-token verification, then signing in. The dance otherwise exchanges codes straight at the provider and never runs our client.
  test "signing in through the client callback completes", context do
    req = create_req_client(context.main_instance)
    callback = sign_in_callback(req, context)

    {:ok, visit} = apply_with_repo_sync(fn -> Req.get(req, url: callback, redirect: false) end)
    refute visit.status >= 500
    assert visit.status in [302, 303]
  end

  # The callback URL the provider sends a signed-in user back to, carrying a fresh code.
  defp sign_in_callback(req, context) do
    {provider_key, provider_config} =
      build_provider_config(context.client, context.discovery_document_uri, %{
        response_type: "code",
        scope: "openid profile email"
      })

    Config.put([:bonfire_open_id, :openid_connect_providers], [{provider_key, provider_config}])

    callback =
      req
      |> perform_login_flow(get_auth_url(context.client.name), context)
      |> Map.get(:headers)
      |> Map.get("location")
      |> List.first()

    assert callback =~ "/openid/client/"
    assert extract_query_params(callback)["code"]
    callback
  end
end
