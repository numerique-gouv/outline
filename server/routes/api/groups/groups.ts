import Router from "koa-router";
import { Op, WhereOptions } from "sequelize";
import { Model as SequelizeModel } from "sequelize-typescript/dist/model/model/model";
import { MAX_AVATAR_DISPLAY } from "@shared/constants";
import auth from "@server/middlewares/authentication";
import { rateLimiter } from "@server/middlewares/rateLimiter";
import validate from "@server/middlewares/validate";
import { User, Event, Group, GroupUser } from "@server/models";
import { authorize } from "@server/policies";
import {
  presentGroup,
  presentPolicies,
  presentUser,
  presentGroupMembership,
} from "@server/presenters";
import { APIContext } from "@server/types";
import { RateLimiterStrategy } from "@server/utils/RateLimiter";
import pagination from "../middlewares/pagination";
import * as T from "./schema";

const router = new Router();

router.post(
  "groups.list",
  auth(),
  pagination(),
  validate(T.GroupsListSchema),
  async (ctx: APIContext<T.GroupsListReq>) => {
    const { direction, sort, userId, name } = ctx.input.body;
    const { user } = ctx.state.auth;

    let where: WhereOptions<Group> = {
      teamId: user.teamId,
    };

    if (name) {
      where = {
        ...where,
        name: {
          [Op.eq]: name,
        },
      };
    }

    const groups = await Group.filterByMember(userId).findAll({
      where,
      order: [[sort, direction]],
      offset: ctx.state.pagination.offset,
      limit: ctx.state.pagination.limit,
    });

    ctx.body = {
      pagination: ctx.state.pagination,
      data: {
        groups: groups.map(presentGroup),
        groupMemberships: groups
          .map((g) =>
            g.groupMemberships
              .filter((membership) => !!membership.user)
              .slice(0, MAX_AVATAR_DISPLAY)
          )
          .flat()
          .map((membership) =>
            presentGroupMembership(membership, { includeUser: true })
          ),
      },
      policies: presentPolicies(user, groups),
    };
  }
);

router.post(
  "groups.info",
  auth(),
  validate(T.GroupsInfoSchema),
  async (ctx: APIContext<T.GroupsInfoReq>) => {
    const { id } = ctx.input.body;
    const { user } = ctx.state.auth;

    const group = await Group.findByPk(id);
    authorize(user, "read", group);

    ctx.body = {
      data: presentGroup(group),
      policies: presentPolicies(user, [group]),
    };
  }
);

router.post(
  "groups.create",
  rateLimiter(RateLimiterStrategy.TenPerHour),
  auth(),
  validate(T.GroupsCreateSchema),
  async (ctx: APIContext<T.GroupsCreateReq>) => {
    const { name } = ctx.input.body;
    const { user } = ctx.state.auth;
    authorize(user, "createGroup", user.team);
    const g = await Group.create({
      name,
      teamId: user.teamId,
      createdById: user.id,
    });

    // reload to get default scope
    const group = await Group.findByPk(g.id, { rejectOnEmpty: true });

    await Event.create({
      name: "groups.create",
      actorId: user.id,
      teamId: user.teamId,
      modelId: group.id,
      data: {
        name: group.name,
      },
      ip: ctx.request.ip,
    });

    ctx.body = {
      data: presentGroup(group),
      policies: presentPolicies(user, [group]),
    };
  }
);

router.post(
  "groups.update",
  auth(),
  validate(T.GroupsUpdateSchema),
  async (ctx: APIContext<T.GroupsUpdateReq>) => {
    const { id, name } = ctx.input.body;
    const { user } = ctx.state.auth;

    const group = await Group.findByPk(id);
    authorize(user, "update", group);

    group.name = name;

    if (group.changed()) {
      await group.save();
      await Event.create({
        name: "groups.update",
        teamId: user.teamId,
        actorId: user.id,
        modelId: group.id,
        data: {
          name,
        },
        ip: ctx.request.ip,
      });
    }

    ctx.body = {
      data: presentGroup(group),
      policies: presentPolicies(user, [group]),
    };
  }
);

router.post(
  "groups.delete",
  auth(),
  validate(T.GroupsDeleteSchema),
  async (ctx: APIContext<T.GroupsDeleteReq>) => {
    const { id } = ctx.input.body;
    const { user } = ctx.state.auth;

    const group = await Group.findByPk(id);
    authorize(user, "delete", group);

    await group.destroy();
    await Event.create({
      name: "groups.delete",
      actorId: user.id,
      modelId: group.id,
      teamId: group.teamId,
      data: {
        name: group.name,
      },
      ip: ctx.request.ip,
    });

    ctx.body = {
      success: true,
    };
  }
);

router.post(
  "groups.memberships",
  auth(),
  pagination(),
  validate(T.GroupsMembershipsSchema),
  async (ctx: APIContext<T.GroupsMembershipsReq>) => {
    const { id, query } = ctx.input.body;
    const { user } = ctx.state.auth;

    const group = await Group.findByPk(id);
    authorize(user, "read", group);
    let userWhere;

    if (query) {
      userWhere = {
        name: {
          [Op.iLike]: `%${query}%`,
        },
      };
    }

    const memberships = await GroupUser.findAll({
      where: {
        groupId: id,
      },
      order: [["createdAt", "DESC"]],
      offset: ctx.state.pagination.offset,
      limit: ctx.state.pagination.limit,
      include: [
        {
          model: User,
          as: "user",
          where: userWhere,
          required: true,
        },
      ],
    });

    ctx.body = {
      pagination: ctx.state.pagination,
      data: {
        groupMemberships: memberships.map((membership) =>
          presentGroupMembership(membership, { includeUser: true })
        ),
        users: memberships.map((membership) => presentUser(membership.user)),
      },
    };
  }
);

router.post(
  "groups.add_user",
  auth(),
  validate(T.GroupsAddUserSchema),
  async (ctx: APIContext<T.GroupsAddUserReq>) => {
    const { id, userId } = ctx.input.body;
    const actor = ctx.state.auth.user;

    const user = await User.findByPk(userId);
    authorize(actor, "read", user);

    let group = await Group.findByPk(id);
    authorize(actor, "update", group);

    let membership = await GroupUser.findOne({
      where: {
        groupId: id,
        userId,
      },
    });

    if (!membership) {
      await group.$add("user", user, {
        through: {
          createdById: actor.id,
        },
      });
      // reload to get default scope
      membership = await GroupUser.findOne({
        where: {
          groupId: id,
          userId,
        },
        rejectOnEmpty: true,
      });

      // reload to get default scope
      group = await Group.findByPk(id, { rejectOnEmpty: true });

      await Event.create({
        name: "groups.add_user",
        userId,
        teamId: user.teamId,
        modelId: group.id,
        actorId: actor.id,
        data: {
          name: user.name,
        },
        ip: ctx.request.ip,
      });
    }

    ctx.body = {
      data: {
        users: [presentUser(user)],
        groupMemberships: [
          presentGroupMembership(membership, { includeUser: true }),
        ],
        groups: [presentGroup(group)],
      },
    };
  }
);

router.post(
  "groups.remove_user",
  auth(),
  validate(T.GroupsRemoveUserSchema),
  async (ctx: APIContext<T.GroupsRemoveUserReq>) => {
    const { id, userId } = ctx.input.body;
    const actor = ctx.state.auth.user;

    let group = await Group.findByPk(id);
    authorize(actor, "update", group);

    const user = await User.findByPk(userId);
    authorize(actor, "read", user);

    await group.$remove("user", user);
    await Event.create({
      name: "groups.remove_user",
      userId,
      modelId: group.id,
      teamId: user.teamId,
      actorId: actor.id,
      data: {
        name: user.name,
      },
      ip: ctx.request.ip,
    });

    // reload to get default scope
    group = await Group.findByPk(id, { rejectOnEmpty: true });

    ctx.body = {
      data: {
        groups: [presentGroup(group)],
      },
    };
  }
);

router.patch("groups/:id", async (ctx) => {
  const { id } = ctx.params;

  const arrayUsers: Array<{ value: number; email: string; type: string }> =
    ctx.request.body?.["Operations"]?.[0]?.value ?? null;

  const arrayEmailAddresses: string[] = arrayUsers.map((user) => user.email);

  let group = await Group.findOne({
    where: {
      id,
    },
    rejectOnEmpty: true,
  });

  let groupUsers = await GroupUser.findOne({
    where: {
      groupId: id,
    },
    // rejectOnEmpty: true,
  });

  const arrayUserModels: User[] = await User.findAll({
    where: {
      email: arrayEmailAddresses,
    },
  });

  const authorId = process.env.DESK_UUID || null;

  if (group instanceof SequelizeModel && authorId) {
    await Promise.all(
      arrayUserModels.map(async (userModel) => {
        let membership = await GroupUser.findOne({
          where: {
            groupId: id,
            userId: userModel.id,
          },
        });

        if (!membership) {
          if (ctx.request.body?.["Operations"]?.[0]?.op === "add") {
            await group.$add("user", userModel, {
              through: {
                createdById: authorId,
              },
            });

            if (group.changed()) {
              await group.save();

              await Event.create({
                name: "groups.add_user",
                userId: userModel.id,
                teamId: userModel.teamId,
                modelId: group.id,
                // actorId: actor.id,
                actorId: authorId,
                data: {
                  name: userModel.name,
                },
                ip: ctx.request.ip,
              });

              // reload to get default scope
              membership = await GroupUser.findOne({
                where: {
                  groupId: group.id,
                  userId: userModel.id,
                },
                // rejectOnEmpty: true,
              });
              groupUsers = membership;

              // reload to get default scope
              group = await Group.findByPk(group.id, { rejectOnEmpty: true });
            }
          }
        }

        if (
          ctx.request.body?.["Operations"]?.[0]?.op === "remove" &&
          membership
        ) {
          await group.$remove("user", userModel);

          if (group.changed()) {
            await group.save();

            await Event.create({
              name: "groups.remove_user",
              userId: userModel.id,
              teamId: userModel.teamId,
              modelId: group.id,
              actorId: authorId,
              data: {
                name: userModel.name,
              },
              ip: ctx.request.ip,
            });

            membership = await GroupUser.findOne({
              where: {
                groupId: group.id,
                userId: userModel.id,
              },
              // rejectOnEmpty: true,
            });
            groupUsers = membership;

            // reload to get default scope
            group = await Group.findByPk(group.id, { rejectOnEmpty: true });
          }
        }
      })
    );
  }

  ctx.body = {
    ok: true,
    group,
    groupUsers,
    arrayUserModels,
  };
});

export default router;
