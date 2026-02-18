import { ArgumentsHost, ExceptionFilter, NotFoundException } from '@nestjs/common';
import { IpsRuntime } from '../module/runtime';
export declare class IpsNotFoundFilter implements ExceptionFilter {
    private readonly runtime?;
    constructor(runtime?: IpsRuntime | undefined);
    catch(exception: NotFoundException, host: ArgumentsHost): void;
}
