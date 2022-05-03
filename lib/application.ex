defmodule Bonfire.OpenID.Application do
  use Application
  use Supervisor

  def start(_type, _args) do
    children = [
      worker(OpenIDConnect.Worker, [Application.get_env(:bonfire_open_id, :openid_connect_providers, [])]),
    ]

    opts = [strategy: :one_for_one, name: Bonfire.OpenID.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
