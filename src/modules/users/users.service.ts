import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './users.entity';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';


@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  findAll(): Promise<User[]> {
    return this.usersRepository.find();
  }

  findOne(id: string): Promise<User | null> {
    return this.usersRepository.findOneBy({ id });
  }
  async findByEmailOrUsername(identifier: string): Promise<User | null> {
    // Regex simples só pra validar estrutura de email
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);
  
    if (isEmail) {
      // normaliza email para lowercase
      return this.usersRepository.findOne({
        where: { email: identifier.toLowerCase().trim() },
      });
    }
  
    // caso contrário, trata como username
    return this.usersRepository.findOne({
        where: { username: identifier.toLowerCase().trim() },     
      });
  }
  

  async createUser(username: string, password_raw: string, email: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password_raw, 10);
    const user = this.usersRepository.create({
      username,
      email,
      password: hashedPassword,
    });
    return this.usersRepository.save(user);
  }

  async updateUser(id: string, updateUserData: UpdateUserDto): Promise<User> {
    const user = await this.usersRepository.findOneBy({ id });
    if (!user) {
      throw new NotFoundException(`Usuário com id ${id} não encontrado`);
    }

    // Atualiza só os campos enviados
    Object.assign(user, updateUserData);

    return this.usersRepository.save(user);
  }
  async removeUser(id: string): Promise<void> {
    const result = await this.usersRepository.delete(id);

    if (result.affected === 0) {
      throw new NotFoundException(`Usuário com id ${id} não encontrado`);
    }
  }
}
