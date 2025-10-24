from utils.router import MainRouter, DbRouter


class NeuraverseRouter(MainRouter, DbRouter):
    def get_choices(self):
        return ['Start daily']

    def route(self, task, action):
        return dict(zip(self.get_choices(), [task.infinity_run_daily]))[action]

    @property
    def action(self):
        self.start_db_router()
        return self.get_action()
