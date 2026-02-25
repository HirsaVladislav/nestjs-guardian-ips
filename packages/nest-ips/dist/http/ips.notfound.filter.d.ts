import { ArgumentsHost, ExceptionFilter, NotFoundException } from '@nestjs/common';
import { IpsRuntime } from '../module/runtime';
export declare class IpsNotFoundFilter implements ExceptionFilter {
    private readonly runtime?;
    constructor(runtime?: IpsRuntime | undefined);
    /** For HTTP 404s without a matched route, records behavior signal and preserves JSON response semantics. */
    catch(exception: NotFoundException, host: ArgumentsHost): void;
}
