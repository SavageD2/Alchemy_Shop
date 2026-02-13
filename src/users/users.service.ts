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
    private userRepository: Repository<User>,
  ) { }

  async create(createUserDto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = this.userRepository.create({
      email: createUserDto.email.toLowerCase(),
      password: hashedPassword,
      role: createUserDto.role,
      shopId: createUserDto.shopId,
    });
    return this.userRepository.save(newUser);
  }

  findByEmail(email: string) {
    return this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.shop', 'shop') // On joint la relation avec Shop
      .where('user.email = :email', { email })
      .addSelect('user.password')
      .getOne();
  }

  findAll() {
    return this.userRepository.find({ relations: ['shop'] });
  }
}