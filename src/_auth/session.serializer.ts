import { Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';
import { DoneCallback } from 'passport';
import { User, UsersService } from 'src/_users/users.service';

// get id type from User
type UserPayload = User['id'];

@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor(private readonly usersService: UsersService) {
    super();
  }

  serializeUser(user: User, done: DoneCallback) {
    const payload = user.id;
    done(null, payload);
  }
  async deserializeUser(payload: UserPayload, done: DoneCallback) {
    const user = await this.usersService.findOneById(payload);
    done(null, user);
  }
}
