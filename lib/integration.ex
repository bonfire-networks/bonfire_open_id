defmodule Bonfire.OpenID do
  @moduledoc "./README.md" |> File.stream!() |> Enum.drop(1) |> Enum.join()

  use Bonfire.Common.Utils
  alias Bonfire.Me.Users
  alias Bonfire.Me.Accounts
  alias Boruta.Oauth.ResourceOwner

  @behaviour Boruta.Oauth.ResourceOwners

  @impl Boruta.Oauth.ResourceOwners
  def get_by(username: username) do
    get_user(username)
  end

  def get_by(sub: sub) do
    get_user(sub)
  end

  defp get_user(id_or_username) do
    with %{} = user <- Users.get_current(id_or_username) do
      {:ok,
       %ResourceOwner{
         sub: to_string(user.id),
         username: user.character.username,
         # TODO include email, etc?
         last_login_at: nil
       }}
    else
      _ ->
        error(id_or_username, l("User not found."))
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def check_password(resource_owner, password) do
    case Accounts.login(%{
           email_or_username: resource_owner.username,
           password: password
         }) do
      {:ok, account, user} ->
        :ok

      _ ->
        error(resource_owner, l("Invalid email or password."))
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def authorized_scopes(%ResourceOwner{}), do: []

  @impl Boruta.Oauth.ResourceOwners
  def claims(_resource_owner, _scope), do: %{}
end
