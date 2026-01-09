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
      true -> err(opts, "Invalid options to get user")
    end
    |> flood("get_by with opts #{inspect(opts)}")
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
    |> flood("get_user with conn")
  end

  def get_user(%{id: id} = current_user) do
    {:ok,
     %ResourceOwner{
       sub: id,
       # TODO include email, etc?
       username:
         e(current_user, :character, :username, nil) ||
           e(current_account(current_user), :email, :email_address, nil),
       # TODO: are we recording last seen on login and/or when the user was last active?
       last_login_at:
         if(Types.is_uid?(id),
           do: Bonfire.Social.Seen.last_date(id, current_account_id(current_user))
         ) || e(current_user, :last_login_at, nil)
     }}
  end

  def get_user(other), do: err(other, "Invalid options to get user")

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
  def authorized_scopes(%ResourceOwner{} = _resource_owner) do
    # TODO: customize per user based on instance roles/boundaries
    Bonfire.OpenID.Provider.ClientApps.scopes_structs()
  end

  @impl Boruta.Oauth.ResourceOwners
  def claims(%ResourceOwner{} = resource_owner, scope) do
    # last_login =
    #   case resource_owner.last_login_at do
    #     %DateTime{} = dt -> DateTime.to_iso8601(dt)
    #     %NaiveDateTime{} = ndt -> NaiveDateTime.to_iso8601(ndt)
    #     val when is_binary(val) -> val
    #     _ -> nil
    #   end

    # TODO: Add more claims?
    %{
      "sub" => resource_owner.sub,
      "name" => resource_owner.username
      # "last_login_at" => last_login
    }
    # TODO: FIXME: claims should be filtered by scope
    |> Map.merge(resource_owner.extra_claims || %{})
  end
end
