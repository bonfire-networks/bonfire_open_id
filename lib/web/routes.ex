defmodule Bonfire.OpenID.Web.Routes do
  @behaviour Bonfire.UI.Common.RoutesModule

  defmacro __using__(_) do
    quote do
      import Bonfire.OpenID.Plugs.ClientID

      def check_provider_enabled(conn, _opts) do
        if System.get_env("ENABLE_SSO_PROVIDER") == "true" do
          conn
        else
          conn
          |> send_resp(404, "SSO provider endpoints are disabled")
          |> halt()
        end
      end

      # client routes

      scope "/openid/client", Bonfire.OpenID.Web do
        pipe_through([:browser, :load_authorization])

        # make sure to comment in prod!
        # get("/test", ClientController, :attempt_login_or_create)

        get("/:provider", ClientController, :create)
      end

      scope "/oauth/client", Bonfire.OpenID.Web do
        pipe_through([:browser, :load_authorization])

        # make sure to comment in prod!
        # get("/test", ClientController, :attempt_login_or_create)

        get("/:provider", ClientController, :create)
      end

      # server/provider routes

      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:check_provider_enabled, :basic, :validate_client_id])

        post("/revoke", RevokeController, :revoke)
        post("/introspect", IntrospectController, :introspect)
      end

      # Token issuance — throttled (brute-force auth vector)
      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:check_provider_enabled, :basic, :validate_client_id, :throttle_forms])

        post("/token", TokenController, :token)
      end

      scope "/oauth" do
        pipe_through([:check_provider_enabled, :basic, :load_authorization, :validate_client_id])

        get("/authorize", Bonfire.OpenID.Web.Oauth.AuthorizeController, :authorize)
        get("/ready", Bonfire.OpenID.Web.Oauth.ReadyController, :ready)

        # NOTE: points to OpenID userinfo endpoint instead
        get("/userinfo", Bonfire.OpenID.Web.Openid.UserinfoController, :userinfo)
        post("/userinfo", Bonfire.OpenID.Web.Openid.UserinfoController, :userinfo)
      end

      # Authorize POST (consent submission) — throttled
      scope "/oauth" do
        pipe_through([
          :check_provider_enabled,
          :basic,
          :load_authorization,
          :validate_client_id,
          :throttle_forms
        ])

        post("/authorize", Bonfire.OpenID.Web.Oauth.AuthorizeController, :authorize)
      end

      scope "/openid" do
        pipe_through([:check_provider_enabled, :basic, :load_authorization])

        get("/authorize", Bonfire.OpenID.Web.Openid.AuthorizeController, :authorize)
        get("/userinfo", Bonfire.OpenID.Web.Openid.UserinfoController, :userinfo)
        post("/userinfo", Bonfire.OpenID.Web.Openid.UserinfoController, :userinfo)
        get("/jwks", Bonfire.OpenID.Web.Openid.JwksController, :jwks_index)

        get "/register/:client_id",
            Bonfire.OpenID.Web.Openid.ClientRegistrationController,
            :retrieve

        put "/register/:client_id",
            Bonfire.OpenID.Web.Openid.ClientRegistrationController,
            :update

        delete "/register/:client_id",
               Bonfire.OpenID.Web.Openid.ClientRegistrationController,
               :delete
      end

      # Token issuance and dynamic client registration — throttled
      scope "/openid" do
        pipe_through([:check_provider_enabled, :basic, :load_authorization, :throttle_forms])

        post("/token", Bonfire.OpenID.Web.Oauth.TokenController, :token)
        post("/register", Bonfire.OpenID.Web.Openid.ClientRegistrationController, :register)
      end

      scope "/.well-known", Bonfire.OpenID.Web.Openid do
        pipe_through([:check_provider_enabled, :basic])

        get("/openid-configuration", UserinfoController, :openid_discovery)
      end

      scope "/.well-known", Bonfire.OpenID.Web.Oauth do
        pipe_through([:check_provider_enabled, :basic])

        get("/oauth-authorization-server", IntrospectController, :oauth_metadata)
      end

      scope "/.well-known", Bonfire.OpenID.Web.Oauth do
        pipe_through([:basic])

        get("/oauth-client", IntrospectController, :oauth_client_metadata)
      end
    end
  end
end
