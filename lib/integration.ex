defmodule Bonfire.OpenID do
  @moduledoc "./README.md" |> File.stream!() |> Enum.drop(1) |> Enum.join()

  use Bonfire.Common.Utils
  alias Bonfire.Me.Users
  alias Bonfire.Me.Accounts
  alias Boruta.Oauth.ResourceOwner

  # TODO: upgrade to Boruta 3.0+
  @behaviour Boruta.Oauth.ResourceOwners

  @impl Boruta.Oauth.ResourceOwners
  def get_by(username: username) do
    get_user(username)
  end

  def get_by(sub: sub) do
    get_user(sub)
  end

  def get_by(opts) when is_list(opts) do
    cond do
      # NOTE: opts can now also include scope
      Keyword.has_key?(opts, :sub) -> get_user(opts[:sub])
      Keyword.has_key?(opts, :username) -> get_user(opts[:username])
      true -> error(opts, "Invalid options to get user")
    end
  end

  def get_user(id_or_username) when is_binary(id_or_username) do
    with %{id: _user_id} = user <- Users.get_current(id_or_username) do
      get_user(user)
    else
      _ ->
        error(id_or_username, l("User not found."))
    end
  end

  def get_user(%Plug.Conn{} = conn) do
    case current_user(conn) do
      id when is_binary(id) -> get_user(id)
      %{} = user -> get_user(user)
      _ -> error(conn, "User not found")
    end
  end

  def get_user(%{id: id} = current_user) do
    {:ok,
     %ResourceOwner{
       sub: id,
       username: e(current_user, :character, :username, nil) || e(current_user, :email, nil),
       # TODO include email, etc?
       last_login_at:
         if(Types.is_uid?(id),
           do: Bonfire.Social.Seen.last_date(id, current_account_id(current_user))
         ) || e(current_user, :last_login_at, nil)
     }}
  end

  def get_user(other), do: error(other, "Could not find user")

  @impl Boruta.Oauth.ResourceOwners
  def check_password(resource_owner, password) do
    case Accounts.login(%{
           email_or_username: resource_owner.username,
           password: password
         }) do
      {:ok, _account, _user} ->
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
