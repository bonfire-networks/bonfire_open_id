defmodule Bonfire.OpenID.Web.Oauth.ReadyController do
  use Bonfire.UI.Common.Web, :controller
  alias Bonfire.OpenID.Web.OauthView

  def ready(%Plug.Conn{} = conn, %{"code" => code}) do
    conn
    |> put_view(OauthView)
    |> render("error.html",
      error: "Ready",
      error_description: "Copy/paste your authentication code into the app: #{code}"
    )
  end
end
