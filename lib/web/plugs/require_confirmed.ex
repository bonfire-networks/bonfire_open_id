defmodule Bonfire.OpenID.Plugs.RequireConfirmed do
  @moduledoc """
  Returns 403 if user email is not confirmed.

  This plug enforces email confirmation for API endpoints. When a user has
  a valid token but hasn't confirmed their email, this returns a 403 response
  with "Your login is missing a confirmed e-mail address".

  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, _opts) do
    # Only block authenticated users with explicitly unconfirmed email
    if conn.assigns[:current_user] && conn.assigns[:user_email_confirmed?] == false do
      conn
      |> put_status(403)
      |> json(%{"error" => "Your login is missing a confirmed e-mail address"})
      |> halt()
    else
      conn
    end
  end
end
