import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  //! session code
  // async canActivate(context: ExecutionContext) {
  //   const result = await super.canActivate(context);
  //   const request = context.switchToHttp().getRequest();
  //   await super.logIn(request);
  //   return !!result;
  // }
}
