defmodule Bonfire.OpenID.Web.Routes do
  def declare_routes, do: nil

  defmacro __using__(_) do
    quote do
      import Bonfire.OpenID.Plugs.ClientID

      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:basic, :validate_client_id])

        post("/revoke", RevokeController, :revoke)
        post("/token", TokenController, :token)
        post("/introspect", IntrospectController, :introspect)
      end

      scope "/openid", Bonfire.OpenID.Web.Openid do
        pipe_through([:basic, :load_current_auth])

        get("/userinfo", UserinfoController, :userinfo)
        post("/userinfo", UserinfoController, :userinfo)
        get("/jwks", JwksController, :jwks_index)
      end

      scope "/.well-known", Bonfire.OpenID.Web.Openid do
        pipe_through([:basic])

        get("/openid-configuration", UserinfoController, :discovery)
      end

      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:basic, :load_current_auth, :validate_client_id])

        get("/authorize", AuthorizeController, :authorize)
        get("/ready", ReadyController, :ready)
      end

      scope "/openid", Bonfire.OpenID.Web.Openid do
        pipe_through([:basic, :load_current_auth])

        get("/authorize", AuthorizeController, :authorize)
      end

      scope "/openid_client", Bonfire.OpenID.Web do
        pipe_through([:browser, :load_current_auth])

        # make sure to comment in prod!
        # get("/test", ClientController, :attempt_login_or_create)

        get(":provider", ClientController, :create)
      end
    end
  end
end
