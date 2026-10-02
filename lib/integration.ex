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
    |> debug("get_by with opts #{inspect(opts)}")
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
    |> debug("get_user with conn")
  end

  def get_user(%{id: id} = current_user) do
    {:ok,
     %ResourceOwner{
       sub: id,
       # TODO include email, etc?
       username:
         e(current_user, :character, :username, nil) ||
           e(current_account(current_user), :email, :email_address, nil),
       # last-seen edge is written per-profile at login (subject=account, object=user); read it back via the account-preloaded current_user so subject→account, object=user matches.
       last_login_at:
         if(current_user, do: Bonfire.Social.Seen.last_date(current_user, current_user)) ||
           e(current_user, :last_login_at, nil)
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

      e ->
        error(e, "Could not authenticate user")
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
      "sub" => resource_owner.sub
      # "last_login_at" => last_login
    }
    |> Map.merge(scoped_claims(resource_owner, Boruta.Oauth.Scope.split(scope)))
    |> Map.merge(resource_owner.extra_claims || %{})
  end

  # Claims that only the granted scope entitles the client to. One user lookup serves both groups, and none happens at all when no granted scope calls for either. Loaded here rather than carried on the ResourceOwner because Boruta merges `extra_claims` into every id_token regardless of scope, so anything parked there would leak to clients that never asked.
  defp scoped_claims(%ResourceOwner{sub: sub, username: username}, granted) do
    # `profile` is the OIDC scope for the profile claims; Mastodon clients ask for `read` instead and expect the same
    profile? = Enum.any?(["profile", "read"], &(&1 in granted))
    email? = "email" in granted

    if profile? or email? do
      user = Users.get_current(sub)

      Map.merge(
        if(profile?, do: profile_claims(user, username), else: %{}),
        if(email?, do: email_claims(user, sub), else: %{})
      )
    else
      %{}
    end
  end

  # `name` is the display name; the handle belongs in `preferred_username`, which is what `ResourceOwner.username` holds.
  defp profile_claims(user, username) do
    case e(user, :profile, :name, nil) do
      name when is_binary(name) -> %{"preferred_username" => username, "name" => name}
      _ -> %{"preferred_username" => username}
    end
  end

  defp email_claims(user, sub) do
    case account_email(user) do
      %{email_address: address} = email when is_binary(address) ->
        %{"email" => address, "email_verified" => not is_nil(e(email, :confirmed_at, nil))}

      _ ->
        warn(sub, "email scope was granted but no email address could be loaded for the user")
        %{}
    end
  end

  defp account_email(user) do
    user
    |> current_account()
    |> Bonfire.Common.Repo.maybe_preload(:email)
    |> e(:email, nil)
  end
end
