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
        pipe_through([:browser, :load_current_auth])

        # make sure to comment in prod!
        # get("/test", ClientController, :attempt_login_or_create)

        get("/:provider", ClientController, :create)
      end

      scope "/oauth/client", Bonfire.OpenID.Web do
        pipe_through([:browser, :load_current_auth])

        # make sure to comment in prod!
        # get("/test", ClientController, :attempt_login_or_create)

        get("/:provider", ClientController, :create)
      end

      # server/provider routes

      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:check_provider_enabled, :basic, :validate_client_id])

        post("/revoke", RevokeController, :revoke)
        post("/token", TokenController, :token)
        post("/introspect", IntrospectController, :introspect)
      end

      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:check_provider_enabled, :basic, :load_current_auth, :validate_client_id])

        get("/authorize", AuthorizeController, :authorize)
        post("/authorize", AuthorizeController, :authorize)
        get("/ready", ReadyController, :ready)
      end

      scope "/openid", Bonfire.OpenID.Web.Openid do
        pipe_through([:check_provider_enabled, :basic, :load_current_auth])

        get("/authorize", AuthorizeController, :authorize)
        get("/userinfo", UserinfoController, :userinfo)
        post("/userinfo", UserinfoController, :userinfo)
        get("/jwks", JwksController, :jwks_index)
      end

      scope "/.well-known", Bonfire.OpenID.Web.Openid do
        pipe_through([:check_provider_enabled, :basic])

        get("/openid-configuration", UserinfoController, :discovery)
      end
    end
  end
end
