defmodule Bonfire.OpenID.Integration do
  import Where
  alias Bonfire.Common.Config
  alias Bonfire.Common.Utils
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
    with {:ok, user} <- Users.get_current(id_or_username) do
      {:ok, %ResourceOwner{
        sub: to_string(user.id),
        username: user.character.username,
        last_login_at: nil # TODO
      }}
    else
      _ -> {:error, "User not found."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def check_password(resource_owner, password) do
    case Accounts.login(%{email_or_username: resource_owner.username, password: password}) do
      {:ok, account, user} -> :ok
      _ -> {:error, "Invalid email or password."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def authorized_scopes(%ResourceOwner{}), do: []

  @impl Boruta.Oauth.ResourceOwners
  def claims(_resource_owner, _scope), do: %{}
end
