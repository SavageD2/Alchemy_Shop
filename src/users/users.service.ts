import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm/repository/Repository.js';
import { InjectRepository } from '@nestjs/typeorm/dist/common/typeorm.decorators';

@Injectable()
export class UsersService {

  constructor(
    @InjectRepository(User) 
    private userRepository: Repository<User>
  ) {}

  async create(createUserDto: CreateUserDto) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = this.userRepository.create({
      ...createUserDto,
      email: createUserDto.email.toLocaleLowerCase(),
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      password: hashedPassword,
    });
    return this.userRepository.save(newUser); 
  }
    
  }
