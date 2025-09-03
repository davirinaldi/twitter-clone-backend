import { Controller, Get, Post, Put, Delete, Param, Body, NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './users.entity';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // Criar usuário
  @Post()
  async create(@Body() createUserData: CreateUserDto): Promise<User> {
    return this.usersService.createUser(
      createUserData.username,
      createUserData.password,
      createUserData.email,
    );
  }

  // Buscar todos
  @Get()
  async findAll(): Promise<User[]> {
    return this.usersService.findAll();
  }

  // Buscar por id
  @Get(':id')
  async findOne(@Param('id') id: string): Promise<User> {
    const user = await this.usersService.findOne(id);
    if (!user) {
      throw new NotFoundException(`Usuário com id ${id} não encontrado`);
    }
    return user;
  }

  // Atualizar (passa o DTO inteiro para o service)
  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body() updateUserData: UpdateUserDto,
  ): Promise<User> {
    return this.usersService.updateUser(id, updateUserData);
  }
  @Delete(':id')
  async remove(@Param('id') id: string): Promise<{ message: string }> {
    await this.usersService.removeUser(id);
    return { message: `Usuário com id ${id} deletado com sucesso` };
  }
}
