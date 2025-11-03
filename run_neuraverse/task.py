import json

from utils.client import Client
from utils.utils import (retry, check_res_status, get_utc_now,
                         get_data_lines, sleep, Logger,
                         read_json, Contract, generate_random_hex_string,
                         get_utc_now, approve_asset, asset_balance, get_decimals, approve_if_insufficient_allowance,
                         generate_random, retry_js, JSException, ModernTask, get_session, get_gas_params, estimate_gas)
from utils.galxe_utils.captcha import CapmonsterSolver
from .config import CAPTCHA_API_KEY, SLEEP_FROM_TO
import random
from decimal import Decimal, getcontext
from .paths import ANKR_ROUTER_ABI
import time
from .utils import pass_transaction
from utils.models import RpcProviders
from eth_abi import encode
from eth_utils import to_hex
from the_trivia_api_library import TriviaAPIClient, EnumCategory, EnumDifficulty
import asyncio
import concurrent.futures
from datetime import datetime, timedelta, timezone


getcontext().prec = 60
Q96 = Decimal(2) ** 96
FEE_DENOM = Decimal(1_000_000)
SYMBOL_ALIASES = {
    "ANKR": "WANKR",
}


class Task(Logger, ModernTask):
    def __init__(self, session, client: Client, db_manager):
        self.session = session
        self.client = client
        self.db_manager = db_manager
        super().__init__(self.client.address, additional={'pk': self.client.key,
                                                          'proxy': self.session.proxies.get('http')})
        self.captcha_solver = CapmonsterSolver(session=self.session,
                                               api_key=CAPTCHA_API_KEY,
                                               logger=self.logger)
        self.explorer = "https://testnet-blockscout.infra.neuraprotocol.io/tx/"

    @staticmethod
    def seconds_until_next_day(min_delay, max_delay):
        now = datetime.now(timezone.utc)
        next_day = (now + timedelta(days=1)).replace(hour=3, minute=0, second=0, microsecond=0)
        seconds_left = (next_day - now).total_seconds()
        random_delay = random.randint(min_delay, max_delay)
        return int(seconds_left + random_delay)

    @retry()
    @check_res_status()
    async def get_nonce(self, captcha):
        url = 'https://privy.neuraprotocol.io/api/v1/siwe/init'
        headers = {
            'accept': 'application/json',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://neuraverse.neuraprotocol.io',
            'priority': 'u=1, i',
            'privy-app-id': 'cmbpempz2011ll10l7iucga14',
            'privy-ca-id': '88ffcec1-2117-435a-bf72-bbc6125c9ebb',
            'privy-client': 'react-auth:2.25.0',
            'referer': 'https://neuraverse.neuraprotocol.io/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'address': self.client.address,
            'token': captcha
        }
        return await self.session.post(url, json=json_data, headers=headers)

    @retry()
    @check_res_status()
    async def authenticate(self, nonce):
        url = 'https://privy.neuraprotocol.io/api/v1/siwe/authenticate'
        headers = {
            'accept': 'application/json',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://neuraverse.neuraprotocol.io',
            'priority': 'u=1, i',
            'privy-app-id': 'cmbpempz2011ll10l7iucga14',
            'privy-ca-id': '88ffcec1-2117-435a-bf72-bbc6125c9ebb',
            'privy-client': 'react-auth:2.25.0',
            'referer': 'https://neuraverse.neuraprotocol.io/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        msg_to_sign = f'neuraverse.neuraprotocol.io wants you to sign in with your Ethereum account:\n{self.client.address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://neuraverse.neuraprotocol.io\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {get_utc_now()}\nResources:\n- https://privy.io'
        json_data = {
            'message': msg_to_sign,
            'signature': self.client.get_signed_code(msg_to_sign),
            'chainId': 'eip155:1',
            'walletClientType': 'rabby_wallet',
            'connectorType': 'injected',
            'mode': 'login-or-sign-up',
        }
        return await self.session.post(url, json=json_data, headers=headers)

    @retry()
    @check_res_status()
    async def link(self, jwt, nonce):
        url = 'https://privy.neuraprotocol.io/api/v1/siwe/link'
        headers = {
            'accept': 'application/json',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': 'Bearer ' + jwt,
            'content-type': 'application/json',
            'origin': 'https://neuraverse.neuraprotocol.io',
            'priority': 'u=1, i',
            'privy-app-id': 'cmbpempz2011ll10l7iucga14',
            'privy-ca-id': '88ffcec1-2117-435a-bf72-bbc6125c9ebb',
            'privy-client': 'react-auth:2.25.0',
            'referer': 'https://neuraverse.neuraprotocol.io/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        msg_to_sign = f'neuraverse.neuraprotocol.io wants you to sign in with your Ethereum account:\n{self.client.address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://neuraverse.neuraprotocol.io\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {get_utc_now()}\nResources:\n- https://privy.io'
        json_data = {
            'message': msg_to_sign,
            'signature': self.client.get_signed_code(msg_to_sign),
            'chainId': 'eip155:1',
            'walletClientType': 'rabby_wallet',
            'connectorType': 'injected',
        }
        return await self.session.post(url, json=json_data, headers=headers)

    @retry()
    @check_res_status()
    async def refresh_token(self, jwt):
        url = 'https://privy.neuraprotocol.io/api/v1/sessions'
        headers = {
            'accept': 'application/json',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': 'Bearer ' + jwt,
            'content-type': 'application/json',
            'origin': 'https://neuraverse.neuraprotocol.io',
            'priority': 'u=1, i',
            'privy-app-id': 'cmbpempz2011ll10l7iucga14',
            'privy-ca-id': '88ffcec1-2117-435a-bf72-bbc6125c9ebb',
            'privy-client': 'react-auth:2.25.0',
            'referer': 'https://neuraverse.neuraprotocol.io/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'refresh_token': 'deprecated',
        }
        return await self.session.post(url, json=json_data, headers=headers)

    async def login(self):
        while True:
            try:
                captcha = (await self.captcha_solver.solve_turnstile(url='https://neuraverse.neuraprotocol.io/',
                                                                     key='0x4AAAAAAAM8ceq5KhP1uJBt'))['token']
                break
            except KeyError:
                continue
        nonce = (await self.get_nonce(captcha)).json()['nonce']
        jwt = (await self.authenticate(nonce=nonce)).json()['token']
        self.session.headers['Authorization'] = f'Bearer {jwt}'
        while True:
            try:
                captcha = (await self.captcha_solver.solve_turnstile(url='https://neuraverse.neuraprotocol.io/',
                                                                     key='0x4AAAAAAAM8ceq5KhP1uJBt'))['token']
                break
            except KeyError:
                continue
        nonce = (await self.get_nonce(captcha)).json()['nonce']
        await self.link(jwt=jwt, nonce=nonce)
        jwt = (await self.refresh_token(jwt=jwt)).json()['identity_token']
        self.session.headers['Authorization'] = f'Bearer {jwt}'
        trivia_token_from_db = await self.db_manager.get_column(self.client.key, 'trivia_token')
        if not trivia_token_from_db:
            trivia_token = (await self.get_trivia_token()).json()['token']
            await self.db_manager.insert_column(self.client.key, 'trivia_token', trivia_token)
        self.logger.success('Logged in successfully!')

    @retry()
    @check_res_status()
    async def collect_pulse_request(self, pulse_id):
        url = 'https://neuraverse-testnet.infra.neuraprotocol.io/api/events'
        json_data = {
            'type': 'pulse:collectPulse',
            'payload': {
                'id': f'pulse:{pulse_id}',
            },
        }
        return await self.session.post(url, json=json_data)

    async def complete_collect_pulses_task(self):
        pulses = [*range(1, 8)]
        random.shuffle(pulses)
        while pulses:
            pulse_id = pulses.pop()
            await self.collect_pulse_request(pulse_id)
            await sleep(10, 30)
        else:
            self.logger.success("All pulses collected successfully!")

    @retry()
    @check_res_status()
    async def visit_request(self, visit_id):
        url = 'https://neuraverse-testnet.infra.neuraprotocol.io/api/events'
        json_data = {
            'type': visit_id,
        }
        return await self.session.post(url, json=json_data)

    async def complete_visit_task(self):
        visit_places = ["game:visitObservationDeck",
                        "game:visitValidatorHouse",
                        "game:visitOracle",
                        "game:visitFountain"]
        random.shuffle(visit_places)
        while visit_places:
            visit_place = visit_places.pop()
            await self.visit_request(visit_place)
            await sleep(10, 30)
        else:
            self.logger.success("All visits completed successfully!")

    @retry()
    @check_res_status()
    async def get_all_tasks(self):
        url = 'https://neuraverse-testnet.infra.neuraprotocol.io/api/tasks'
        return await self.session.get(url)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 409])
    async def claim_task(self, task):
        url = f'https://neuraverse-testnet.infra.neuraprotocol.io/api/tasks/{task}/claim'
        return await self.session.post(url)

    async def claim_available_tasks(self):
        self.logger.info("Starting claiming tasks...")
        tasks = (await self.get_all_tasks()).json()['tasks']
        for task in tasks:
            if task['status'] == 'claimable':
                await self.claim_task(task['id'])
                self.logger.success(f"Claimed task `{task['description']}` successfully!")
                await sleep(10, 30)

    @retry()
    @check_res_status()
    async def account(self):
        url = 'https://neuraverse-testnet.infra.neuraprotocol.io/api/account'
        return await self.session.get(url)

    @retry()
    @check_res_status(expected_statuses=[200, 201, 403])
    async def faucet_request(self):
        url = 'https://neuraverse.neuraprotocol.io/?section=faucet'
        headers = {
            'accept': 'text/x-component',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'cache-control': 'no-cache',
            'content-type': 'text/plain;charset=UTF-8',
            'next-action': '78459a487b08c86189d6e3cab0b36d8f76eb2b632a',
            'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
            'origin': 'https://neuraverse.neuraprotocol.io',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://neuraverse.neuraprotocol.io/?section=faucet',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.session.headers['User-Agent']
        }
        data = f'["{self.client.address}",267,"{self.session.headers["Authorization"].split("Bearer ")[-1]}",true]'
        return await self.session.post(url, data=data, headers=headers)

    @retry()
    @check_res_status()
    async def faucet_event(self):
        url = 'https://neuraverse-testnet.infra.neuraprotocol.io/api/events'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'uk-UA,uk;q=0.9,ru;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': self.session.headers['Authorization'],
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://neuraverse.neuraprotocol.io',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://neuraverse.neuraprotocol.io/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.session.headers['User-Agent']
        }
        json_data = {
            'type': 'faucet:claimTokens'
        }
        return await self.session.post(url, json=json_data, headers=headers)

    async def faucet(self):
        neura_points = (await self.account()).json()['neuraPoints']
        if neura_points < 50:
            self.logger.error(f"You need to have more than 50 points in your account to faucet. "
                              f"You have only {neura_points} points.")
            return
        faucet_response = await self.faucet_request()
        await self.faucet_event()
        if 'ANKR distribution successful' in faucet_response.text:
            self.logger.success("Successfully faucet!")
        elif 'Address has already received' in faucet_response.text:
            self.logger.info(f"You have already received tANKR today!")
        elif 'This address is not allowed to receive tokens' in faucet_response.text:
            self.logger.error(f"This address is not allowed to receive tokens")
        else:
            self.logger.error(f"Faucet error: {faucet_response.text}")

    getcontext().prec = 60

    Q96 = Decimal(2) ** 96
    FEE_DENOM = Decimal(1_000_000)

    SYMBOL_ALIASES = {
        "ANKR": "WANKR",
    }

    def pick_best_direct_pool(self, data, sym_in, sym_out):
        pools = data["data"]["pools"]
        sym_in = SYMBOL_ALIASES.get(sym_in, sym_in)
        sym_out = SYMBOL_ALIASES.get(sym_out, sym_out)

        candidates = []
        for p in pools:
            t0, t1 = p["token0"]["symbol"], p["token1"]["symbol"]
            if ({t0, t1} == {sym_in, sym_out}) and p.get("sqrtPrice") and p.get("liquidity"):
                try:
                    L = int(p["liquidity"])
                except Exception:
                    L = 0
                candidates.append((L, p))

        if not candidates:
            return None, f"Not found direct pool between {sym_in} and {sym_out} with 0 liquidity."

        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1], None


    def v3_amount_out_single_tick(self,
            amount_in_human: Decimal,
            token_in_is0,
            sqrt_price_x96_str,
            liquidity_str,
            fee_hundredth_bps,
            decimals_in,
            decimals_out,
    ):
        if Decimal(liquidity_str) == 0:
            raise ValueError("Zero liqudity pool")

        S = Decimal(int(sqrt_price_x96_str)) / Q96
        L = Decimal(int(liquidity_str))

        a_in_raw = amount_in_human * (Decimal(10) ** decimals_in)
        a_in_after_fee = a_in_raw * (FEE_DENOM - Decimal(fee_hundredth_bps)) / FEE_DENOM

        if token_in_is0:
            S_next = S + (a_in_after_fee * (S ** 2)) / L
            amount_out_raw = L * (S_next - S)
        else:
            S_next = S - (a_in_after_fee / L)
            if S_next <= 0:
                raise ValueError("Tick border achieved.")
            amount_out_raw = L * (1 / S_next - 1 / S)

        amount_out_human = amount_out_raw / (Decimal(10) ** decimals_out)
        price_impact_percent = abs((S_next - S) / S) * Decimal(100)
        next_sqrt_price_x96 = str(int(S_next * Q96))

        return amount_out_human, price_impact_percent, next_sqrt_price_x96

    def get_amount_out(self, data, amount_in, symbol_in, symbol_out):
        pool, err = self.pick_best_direct_pool(data, symbol_in, symbol_out)
        if err:
            return {"error": err}

        sym_in = SYMBOL_ALIASES.get(symbol_in, symbol_in)
        sym_out = SYMBOL_ALIASES.get(symbol_out, symbol_out)

        t0, t1 = pool["token0"], pool["token1"]
        sym0, sym1 = t0["symbol"], t1["symbol"]

        if sym0 == sym_in and sym1 == sym_out:
            token_in_is0 = True
            dec_in, dec_out = int(t0["decimals"]), int(t1["decimals"])
        elif sym1 == sym_in and sym0 == sym_out:
            token_in_is0 = False
            dec_in, dec_out = int(t1["decimals"]), int(t0["decimals"])
        else:
            return {"error": f"Pool {sym0}/{sym1} is not correct {sym_in}->{sym_out}"}

        sqrt_price = pool["sqrtPrice"]
        liquidity = pool["liquidity"]
        fee = int(pool["fee"])

        amt_out, price_impact, next_sqrt = self.v3_amount_out_single_tick(
            amount_in_human=Decimal(str(amount_in)),
            token_in_is0=token_in_is0,
            sqrt_price_x96_str=sqrt_price,
            liquidity_str=liquidity,
            fee_hundredth_bps=fee,
            decimals_in=dec_in,
            decimals_out=dec_out,
        )

        fee_percent = Decimal(fee) / Decimal(10_000)

        return {
            "pool_id": pool["id"],
            "route": f"{sym0} ↔ {sym1}",
            "direction": f"{sym_in} → {sym_out}",
            "fee": f"{fee_percent}%",
            "amount_in": float(amount_in),
            "token_in": symbol_in,
            "token_out": symbol_out,
            "amount_out": float(amt_out),
            "amount_out_str": f"{amt_out.normalize()} {symbol_out}",
            "price_impact_%": f"{price_impact:.6f}",
            "next_sqrtPriceX96": next_sqrt,
            "note": "Single-tick",
        }

    @retry()
    @check_res_status()
    async def get_swap_data(self):
        url = 'https://api.goldsky.com/api/public/project_cmc8t6vh6mqlg01w19r2g15a7/subgraphs/analytics/1.0.1/gn'
        json_data = {
            'operationName': 'MultiplePools',
            'variables': {
                'poolIds': [
                    '0x9ca089a5ead9fe795be00b1729c592598ed857a4',
                    '0xfd9741523af12334c855635e883c886214276f6d',
                    '0x91deb91c64e61d014a1d128ace2f3709ad005a46',
                    '0x55705b21f8616504cb8914810c445005b2d71c13',
                    '0x9e4115f5df4a2148fa76dced1b25e3acbd0604c2',
                    '0xc2ae694bc61bec029116a21e0ef4724ca15720f4',
                    '0xd0fc96f867e716c203f12a9e1b1202635a46bc8a',
                    '0x2eb6aebdc9acc2a8a191b2c0b0d3fa8f98f19f5c',
                    '0xff303492bc06bc0e7589612526833c2b68dc23d1',
                    '0x7426bf153db20e7967ffdc9c9d210893c28d18c0',
                    '0x444b62eefdd48e05d1dd34e584e40f88afe97957',
                    '0x6e5ea8735176f7d532ae39864dbbfd6a1fc9101a',
                    '0xd310cb55e17669a53ed45b1c8cbf366bf70528b3',
                    '0xca767cf90317d1229d1186eb375f9b6f0a3a2c51',
                    '0xcf2ca6c90ed72b05691d7361b4885b6b76e7498b',
                    '0x3aece25bd94460433dfd1b87c38da293ecc28455',
                    '0x72dc563f5e765219076d3a30add609e26f817c39',
                    '0x5aa58f77027d63e1d48ae36fb231fbbc7d06bf45',
                    '0xa3ed2c43980dba6d42767bde45a0b73e6b63e4ac',
                    '0x0b6604d5d4e6adcf9956e43592efe9481861f5d8',
                    '0x49245d4891ef1edfc6c1c84e89271de054c07b9c',
                ],
            },
            'query': 'query MultiplePools($poolIds: [ID!]) {\n  pools(where: {id_in: $poolIds}) {\n    ...PoolFields\n    __typename\n  }\n}\n\nfragment PoolFields on Pool {\n  id\n  fee\n  token0 {\n    ...TokenFields\n    __typename\n  }\n  token1 {\n    ...TokenFields\n    __typename\n  }\n  sqrtPrice\n  liquidity\n  tick\n  tickSpacing\n  totalValueLockedUSD\n  volumeUSD\n  feesUSD\n  untrackedFeesUSD\n  token0Price\n  token1Price\n  __typename\n}\n\nfragment TokenFields on Token {\n  id\n  symbol\n  name\n  decimals\n  derivedMatic\n  __typename\n}',
        }
        return await self.session.post(url, json=json_data)

    @pass_transaction(success_message="Successfully swapped!")
    async def complete_swap_tx(self, coin_in_addr, coin_out_addr, amount_in, native=True):
        self.client.define_new_provider(RpcProviders.NEURA_TESTNET.value)
        deadline_ms = int(time.time() * 1000) + 20 * 60 * 1000
        inner = self.encode_inner_swap(coin_in_addr,
                                       coin_out_addr,
                                       self.client.address,
                                       deadline_ms,
                                       amount_in)
        payload_data_bytes = self.client.w3.to_bytes(hexstr=inner)
        ankr_swap_abi = read_json(ANKR_ROUTER_ABI)
        contract_address = self.client.w3.to_checksum_address('0x5AeFBA317BAba46EAF98Fd6f381d07673bcA6467')
        contract = await Contract(self.client).get_contract(
            contract_address=contract_address,
            abi=ankr_swap_abi)
        transaction = await contract.functions.multicall((payload_data_bytes,)).build_transaction({
            'chainId': await self.client.w3.eth.chain_id,
            'from': self.client.address,
            'nonce': await self.client.w3.eth.get_transaction_count(self.client.address),
            'gasPrice': await self.client.w3.eth.gas_price
        })
        if native:
            transaction['value'] == amount_in
        transaction['gas'] = await self.client.w3.eth.estimate_gas(transaction)
        signed_txn = self.client.w3.eth.account.sign_transaction(transaction, private_key=self.client.key)
        tx_hash = await self.client.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return tx_hash.hex()

    async def swap_task(self):
        self.client.define_new_provider(RpcProviders.NEURA_TESTNET.value)
        COINS = [
            {
                "coin": "ztUSD",
                "contract": "0x9423c6C914857e6DaAACe3b585f4640231505128",
                "decimals": 6,
                'min_balance': 0.002
            },
            {
                "coin": "ANKR",
                "contract": "0xBd833b6eCC30CAEaBf81dB18BB0f1e00C6997E7a",
                "decimals": 18,
                'min_balance': 0.3
            },
            {
                "coin": "tUSDC",
                "contract": "0x5f963bE0C8280599b3C716C2Ab1764A7ED3D6822",
                "decimals": 6,
                'min_balance': 0.002
            },
            {
                "coin": "OP",
                "contract": "0x3630388bd5e6927b7B6F8B6Eb5863315D9401401",
                "decimals": 18,
                'min_balance': 0.3
            },
        ]
        coins_with_balances = []
        for coin in COINS:
            if coin['coin'] == "ANKR":
                if (await asset_balance(self)) > 0.3:
                    coins_with_balances.append(coin)
                    continue
            if (await asset_balance(self, coin['contract']) / (10 ** coin['decimals'])) > coin['min_balance']:
                coins_with_balances.append(coin)
        while True:
            try:
                while True:
                    try:
                        # coin_in = random.choice(coins_with_balances)
                        coin_in = COINS[-1] if COINS[-1] in coins_with_balances else None
                        if not coin_in:
                            return
                        coin_out = random.choice([coin for coin in COINS if coin['coin'] != coin_in['coin']])
                        amount_in = round(random.uniform(0.1, 0.3), 5)
                        data = (await self.get_swap_data()).json()
                        amount_out = self.get_amount_out(data,
                                                         amount_in=amount_in,
                                                         symbol_in=coin_in['coin'],
                                                         symbol_out=coin_out['coin'])
                        amount_out = amount_out['amount_out']
                        # amount_out = amount_out - (amount_out * 0.1)
                        break
                    except Exception as e:
                        self.logger.error("Error getting swap data. Trying again...")
                        await sleep(1, 3)
                        continue
                self.logger.info(f"Starting swapping {amount_in} {coin_in['coin']} - {amount_out} {coin_out['coin']}...")
                if coin_in['coin'] != "ANKR":
                    await approve_if_insufficient_allowance(self,
                                                            coin_in['contract'],
                                                            "0x5e06D1bd47dd726A9bcd637e3D2F86B236e50c26",
                                                            legacy=True)
                    await approve_if_insufficient_allowance(self,
                                                            "0x5AeFBA317BAba46EAF98Fd6f381d07673bcA6467",
                                                            coin_in['contract'],
                                                            legacy=True)
                await self.complete_swap_tx(coin_in['contract'],
                                            coin_out['contract'],
                                            int(amount_in * 10 ** coin_in['decimals']),
                                            native=True if coin_in['coin'] == "ANKR" else False)
                break
            except ValueError as e:
                if str(e) == 'Too little received!':
                    self.logger.error("To little received! Trying again...")
                    continue
                elif str(e) == 'STF':
                    self.logger.error("STF! Trying again...")
                    continue
                raise

    def encode_inner_swap(self, token_in, token_out, recipient, deadline_ms, amount_in_wei):
        types = [
            'address', 'address', 'uint256', 'address',
            'uint256', 'uint256', 'uint256', 'uint256'
        ]
        values = [
            token_in,
            token_out,
            0,
            recipient,
            int(deadline_ms),
            int(amount_in_wei),
            27,
            0
        ]
        encoded = encode(types, values)
        return '0x1679c792' + to_hex(encoded)[2:]

    @retry()
    @check_res_status()
    async def get_trivia_token(self):
        return await self.session.get("https://opentdb.com/api_token.php?command=request")

    @staticmethod
    def get_random_question_sync(trivia_token):
        client = TriviaAPIClient(api_key=trivia_token)
        random_category = random.choice([category for category in EnumCategory])
        random_difficulty = random.choice([difficulty for difficulty in EnumDifficulty])
        question = client.get_random_question(
            limit=1,
            categories=[random_category.value],
            difficulties=[random_difficulty.value],
        )
        return question[0]['question']['text']

    @property
    async def random_question(self):
        trivia_token_from_db = await self.db_manager.get_column(self.client.key, 'trivia_token')
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return await loop.run_in_executor(pool, lambda: self.get_random_question_sync(trivia_token_from_db))

    @retry()
    @check_res_status(expected_statuses=[200, 201, 429, 500])
    async def chat_to_oracle_request(self):
        url = 'https://neuraverse-testnet.infra.neuraprotocol.io/api/game/chat/oracle'
        msg = await self.random_question
        json_data = {
            'messages': [
                {
                    'role': 'user',
                    'content': msg,
                }
            ],
        }
        return await self.session.post(url, json=json_data)

    async def chat_to_oracle(self):
        rate_limit = 5
        while True:
            if rate_limit <= 0:
                break
            oracle_response = await self.chat_to_oracle_request()
            if oracle_response.status_code == 429:
                self.logger.info("Rate limit reached. Trying again...")
                rate_limit -= 1
                await sleep(10, 30)
                continue
            elif 'Last error: Requests to the ChatCompletions_Create Operation under Azure OpenAI API version' in oracle_response.text:
                self.logger.info("Rate limit reached. Trying again...")
                await sleep(10, 30)
                continue
            elif oracle_response.status_code in [200, 201]:
                self.logger.success("Successfully sent message to oracle.")
                break
            else:
                self.logger.error(oracle_response.text)
                await sleep(10, 30)
                continue

    @retry()
    @check_res_status(expected_statuses=[200, 201, 429, 500])
    async def chat_to_validators_request(self):
        random_validator = random.choice(['borl', 'talon', 'eldros', 'bullhorn', 'oomi', 'ember'])
        url = f'https://neuraverse-testnet.infra.neuraprotocol.io/api/game/chat/validator/{random_validator}'
        msg = await self.random_question
        json_data = {
            'messages': [
                {
                    'role': 'user',
                    'content': msg
                },
            ],
        }
        return await self.session.post(url, json=json_data)

    async def chat_to_validators(self):
        rate_limit = 10
        while True:
            if rate_limit <= 0:
                break
            validator_response = await self.chat_to_validators_request()
            if validator_response.status_code == 429:
                self.logger.info("Rate limit reached. Trying again...")
                rate_limit -= 1
                await sleep(10, 30)
                continue
            elif 'Last error: Requests to the ChatCompletions_Create Operation under Azure OpenAI API version' in validator_response.text:
                self.logger.info("Rate limit reached. Trying again...")
                await sleep(10, 30)
                continue
            elif validator_response.status_code in [200, 201]:
                self.logger.success("Successfully sent message to validator.")
                break
            else:
                self.logger.error(validator_response.text)
                await sleep(10, 30)
                continue

    async def infinity_run_daily(self):
        while True:
            await self.login()
            await self.complete_collect_pulses_task()
            await self.complete_visit_task()
            await self.claim_available_tasks()
            await self.faucet()
            for _ in range(10):
                await self.swap_task()
            await sleep(5, 10)
            await self.claim_available_tasks()
            for _ in range(random.randint(3, 5)):
                await self.chat_to_oracle()
                await sleep(10, 30)
            for _ in range(random.randint(1, 3)):
                await self.chat_to_validators()
                await sleep(30, 60)
            random_sleep_daily_time = self.seconds_until_next_day(*SLEEP_FROM_TO)
            self.logger.info(f"Sleeping for {random_sleep_daily_time}s before next day...")
            await sleep(random_sleep_daily_time)
