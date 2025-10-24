from .router import NeuraverseRouter
from utils.runner import ModernRunner
from utils.utils import get_session, sleep, get_data_lines, get_new_db_path_name, build_db_path, MaxLenException, Logger
from .task import Task
from .database.engine import NeuraverseDbManager
from .database.models import NeuraverseBaseModel
from .config import *
import os


class NeuraverseRunner(ModernRunner):
    def __init__(self):
        self.Router = NeuraverseRouter
        super().__init__()

    async def run_task(self, data, need_to_sleep=True):
        async with NeuraverseDbManager(build_db_path(self.db_name), NeuraverseBaseModel) as db_manager:
            proxy = data['proxy']
            client = data['client']
            session = get_session('https://neuraverse.neuraprotocol.io', proxy.session_proxy)

            async with Task(session=session,
                            client=client,
                            db_manager=db_manager) as task:
                if need_to_sleep:
                    await sleep(*SLEEP_BETWEEN_WALLETS)
                await self.Router().route(task=task, action=self.action)()

    async def handle_db(self):
        if self.db_name == 'new':
            new_db = get_new_db_path_name()
            async with NeuraverseDbManager(new_db, NeuraverseBaseModel) as db_manager:
                await db_manager.create_tables()
                async with db_manager.session.begin():
                    try:
                        for curr in range(len(self.prepared_data['clients'])):
                                data = {key: value[curr] for key, value in self.prepared_data.items()}
                                pk = data['clients'].key
                                proxy = data['proxies'].proxy
                                await db_manager.create_base_note(pk,
                                                                  proxy)
                    except Exception:
                        os.remove(new_db)
                        raise
            self.db_name = new_db
        async with NeuraverseDbManager(build_db_path(self.db_name), NeuraverseBaseModel) as db_manager:
            return await db_manager.get_run_data()
