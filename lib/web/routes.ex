defmodule Bonfire.OpenID.Web.Routes do
  def declare_routes, do: nil

  defmacro __using__(_) do
    quote do
      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        pipe_through([:basic])

        post("/revoke", RevokeController, :revoke)
        post("/token", TokenController, :token)
        post("/introspect", IntrospectController, :introspect)
      end

      scope "/openid", Bonfire.OpenID.Web.Openid do
        pipe_through([:basic])

        get("/userinfo", UserinfoController, :userinfo)
        post("/userinfo", UserinfoController, :userinfo)
        get("/jwks", JwksController, :jwks_index)
      end

      scope "/.well-known", Bonfire.OpenID.Web.Openid do
        pipe_through([:basic])

        get("/openid-configuration", UserinfoController, :discovery)
      end

      scope "/oauth", Bonfire.OpenID.Web.Oauth do
        # needs current_user
        pipe_through([:browser])

        get("/authorize", AuthorizeController, :authorize)
      end

      scope "/openid", Bonfire.OpenID.Web.Openid do
        # needs current_user
        pipe_through([:browser])

        get("/authorize", AuthorizeController, :authorize)
      end

      scope "/openid_client", Bonfire.OpenID.Web do
        # needs current_user
        pipe_through([:browser, :load_current_auth])

        # make sure to comment in prod!
        # get("/test", ClientController, :attempt_login_or_create)

        get(":provider", ClientController, :create)
      end
    end
  end
end
