from utils.utils import sleep
from utils.models import TxStatusResponse
from curl_cffi.requests.errors import RequestsError
import traceback
from web3.exceptions import TransactionNotFound


def pass_transaction(success_message='Transaction passed'):
    def outer(func):
        async def wrapper(obj, *args, **kwargs):
            logger = obj.logger.bind(func_name=func.__name__, func_module=func.__module__)
            attempts = 10
            completed = False
            while attempts:
                try:
                    if not completed:
                        tx_hash = await func(obj, *args,  **kwargs)
                        completed = True
                    await sleep(7, 10)
                    receipts = await obj.client.w3.eth.get_transaction_receipt(tx_hash)
                    status = receipts.get("status")
                    if status == 1:
                        logger.success(f'{success_message}. HASH - {obj.explorer}{tx_hash}')
                        await sleep()
                        return TxStatusResponse.GOOD, tx_hash
                    else:
                        logger.error(f'Status {status}. Trying again...')
                        attempts -= 1
                        completed = False
                except ValueError as e:
                    message = str(e)
                    if 'Too little received' in message:
                        raise ValueError('Too little received!')
                    elif 'STF' in message:
                        raise ValueError('STF')
                    logger.error(e)
                    return TxStatusResponse.INSUFFICIENT_BALANCE, None
                except TransactionNotFound:
                    logger.error("Transaction not found. Trying again...")
                    await sleep(15, 40)
                    attempts -= 1
                except Exception as e:
                    message = str(e)
                    if 'Proxy Authentication Required' in message:
                        raise RequestsError('Proxy Authentication Required')
                    elif '' == message:
                        raise RequestsError('Strange error!')
                    logger.error(f'Error! {type(e)}{e}[{traceback.format_exc()}]. Trying again...')
                    await sleep(15, 40)
                    attempts -= 1
            else:
                return TxStatusResponse.STATUS_ZERO, None
        return wrapper
    return outer