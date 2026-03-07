/**
 * TRAUMA Discord Bot
 * License verification and management via Discord
 */

require('dotenv').config();
const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, PermissionsBitField } = require('discord.js');
const axios = require('axios');

// Config
const DISCORD_TOKEN = process.env.DISCORD_BOT_TOKEN;
const LICENSE_SERVER = process.env.LICENSE_SERVER || 'http://localhost:3001';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const WELCOME_CHANNEL_ID = process.env.WELCOME_CHANNEL_ID;
const LICENSED_ROLE_ID = process.env.LICENSED_ROLE_ID;

// Create client with all needed intents
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessageReactions
    ]
});

// Store verified users in memory (use database in production)
const verifiedUsers = new Map();

// Slash commands
const commands = [
    new SlashCommandBuilder()
        .setName('verify')
        .setDescription('Verify your TRAUMA license')
        .addStringOption(option =>
            option.setName('key')
                .setDescription('Your TRAUMA license key')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('activate')
        .setDescription('Activate a license (Admin only)')
        .addStringOption(option =>
            option.setName('key')
                .setDescription('License key to activate')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('status')
        .setDescription('Check your license status'),
    
    new SlashCommandBuilder()
        .setName('generate')
        .setDescription('Generate a new license (Admin only)')
        .addStringOption(option =>
            option.setName('user')
                .setDescription('Username for the license')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('License duration in days')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('revoke')
        .setDescription('Revoke a license (Admin only)')
        .addStringOption(option =>
            option.setName('key')
                .setDescription('License key to revoke')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('list')
        .setDescription('List all licenses (Admin only)')
        .addIntegerOption(option =>
            option.setName('limit')
                .setDescription('Number of licenses to show')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('stats')
        .setDescription('Show license server statistics (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('referral')
        .setDescription('Create a referral code (Admin only)')
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Referral name')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('bonus')
                .setDescription('Bonus days for referral')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('extend')
        .setDescription('Extend your license with a referral code')
        .addStringOption(option =>
            option.setName('code')
                .setDescription('Referral code')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('key')
                .setDescription('Your license key')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('mystats')
        .setDescription('Get your license stats via DM'),
    
    new SlashCommandBuilder()
        .setName('ticket')
        .setDescription('Create a support ticket')
        .addStringOption(option =>
            option.setName('subject')
                .setDescription('What do you need help with?')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('checkreminders')
        .setDescription('Check expiring licenses (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('sendreminders')
        .setDescription('Send renewal reminder DMs (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('createpool')
        .setDescription('Create a license pool (Admin only)')
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Pool name')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('count')
                .setDescription('Number of keys (1-100)')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('License duration in days')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('listpools')
        .setDescription('List all license pools (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('claimpool')
        .setDescription('Claim a license from a pool')
        .addStringOption(option =>
            option.setName('poolid')
                .setDescription('Pool ID')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('auditlog')
        .setDescription('View recent audit logs (Admin only)')
        .addIntegerOption(option =>
            option.setName('limit')
                .setDescription('Number of logs to show')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('bulkgenerate')
        .setDescription('Generate multiple licenses at once (Admin only)')
        .addStringOption(option =>
            option.setName('users')
                .setDescription('Comma-separated list of users')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('License duration in days')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('bulkrevoke')
        .setDescription('Revoke multiple licenses at once (Admin only)')
        .addStringOption(option =>
            option.setName('keys')
                .setDescription('Comma-separated list of keys')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for revocation')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('bulkextend')
        .setDescription('Extend multiple licenses at once (Admin only)')
        .addStringOption(option =>
            option.setName('keys')
                .setDescription('Comma-separated list of keys')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('Days to add')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('extendexpiring')
        .setDescription('Extend all licenses expiring soon (Admin only)')
        .addIntegerOption(option =>
            option.setName('withindays')
                .setDescription('Extend licenses expiring within X days')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('adddays')
                .setDescription('Days to add')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('cleanup')
        .setDescription('Remove all revoked licenses (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('adminpanel')
        .setDescription('Send admin control panel to channel (Admin only)'),
    
    new SlashCommandBuilder()
        .setName('help')
        .setDescription('Show TRAUMA bot help')
];

// Register commands
async function registerCommands() {
    const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
    
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(client.user.id),
            { body: commands }
        );
        console.log('Commands registered!');
    } catch (error) {
        console.error('Error registering commands:', error);
    }
}

// Check if user is admin
function isAdmin(userId) {
    const adminIds = process.env.ADMIN_IDS?.split(',') || [];
    return adminIds.includes(userId);
}

// API helper
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const config = {
            method,
            url: `${LICENSE_SERVER}${endpoint}`,
            headers: {
                'x-api-key': ADMIN_API_KEY,
                'Content-Type': 'application/json'
            }
        };
        if (data) config.data = data;
        const response = await axios(config);
        return response.data;
    } catch (error) {
        return { error: error.response?.data?.error || error.message };
    }
}

// Events
client.once('ready', () => {
    console.log(`✅ TRAUMA Discord Bot logged in as ${client.user.tag}`);
    registerCommands();
});

// Welcome new members
client.on('guildMemberAdd', async (member) => {
    try {
        const channel = member.guild.channels.cache.get(WELCOME_CHANNEL_ID);
        if (!channel) return;
        
        const embed = new EmbedBuilder()
            .setColor(0xdc143c)
            .setTitle('🎯 Welcome to TRAUMA')
            .setDescription(`Hey ${member}, welcome to the TRAUMA community!`)
            .addFields(
                { name: '🔐 Get Access', value: 'Use `/verify <your-license-key>` to unlock all features', inline: false },
                { name: '📦 Get a License', value: 'Contact an admin to purchase a license', inline: true },
                { name: '📚 Documentation', value: 'Check out our guides in the channels', inline: true }
            )
            .setThumbnail(member.user.displayAvatarURL())
            .setFooter({ text: 'TRAUMA Security Suite' })
            .setTimestamp();
        
        await channel.send({ content: `<@${member.id}>`, embeds: [embed] });
    } catch (e) {
        console.error('Welcome error:', e.message);
    }
});

// Assign role when user verifies license
async function assignLicensedRole(userId, guild) {
    if (!LICENSED_ROLE_ID || !guild) return;
    
    try {
        const member = await guild.members.fetch(userId);
        if (member && !member.roles.cache.has(LICENSED_ROLE_ID)) {
            await member.roles.add(LICENSED_ROLE_ID);
            console.log(`✅ Assigned licensed role to ${member.user.tag}`);
        }
    } catch (e) {
        console.error('Role assignment error:', e.message);
    }
}

// Remove role when license expires/revoked
async function removeLicensedRole(userId, guild) {
    if (!LICENSED_ROLE_ID || !guild) return;
    
    try {
        const member = await guild.members.fetch(userId);
        if (member && member.roles.cache.has(LICENSED_ROLE_ID)) {
            await member.roles.remove(LICENSED_ROLE_ID);
            console.log(`🔴 Removed licensed role from ${member.user.tag}`);
        }
    } catch (e) {
        console.error('Role removal error:', e.message);
    }
}

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;
    
    const { commandName, user, options } = interaction;
    
    switch (commandName) {
        case 'verify': {
            const key = options.getString('key');
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/license/validate', 'POST', { key });
            
            if (result.valid) {
                verifiedUsers.set(user.id, { key, user: result.user, expires: result.expires });
                
                // Assign licensed role
                await assignLicensedRole(user.id, interaction.guild);
                
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('✅ License Verified')
                    .setDescription(`Welcome to TRAUMA, **${result.user}**!`)
                    .addFields(
                        { name: 'Days Remaining', value: `${result.daysRemaining} days`, inline: true },
                        { name: 'Expires', value: new Date(result.expires).toLocaleDateString(), inline: true },
                        { name: 'Role', value: 'Licensed role assigned! 🎉', inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('❌ License Invalid')
                    .setDescription(result.error || 'License verification failed')
                    .setFooter({ text: 'TRAUMA License System' });
                
                await interaction.editReply({ embeds: [embed] });
            }
            break;
        }
        
        case 'activate': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            const key = options.getString('key');
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/license/activate', 'POST', { key, hardwareId: user.id });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('✅ License Activated')
                    .setDescription(`License activated for **${result.user}**`)
                    .addFields(
                        { name: 'Key', value: `\`${key}\``, inline: false },
                        { name: 'Days Remaining', value: `${result.daysRemaining} days`, inline: true },
                        { name: 'Expires', value: new Date(result.expires).toLocaleDateString(), inline: true }
                    )
                    .setFooter({ text: 'Now shows as ACTIVE in license manager' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('❌ Activation Failed')
                    .setDescription(result.error || 'Activation failed')
                    .setFooter({ text: 'TRAUMA License System' });
                
                await interaction.editReply({ embeds: [embed] });
            }
            break;
        }
        
        case 'status': {
            await interaction.deferReply({ ephemeral: true });
            
            const verified = verifiedUsers.get(user.id);
            if (!verified) {
                const embed = new EmbedBuilder()
                    .setColor(0xffaa00)
                    .setTitle('⚠️ Not Verified')
                    .setDescription('Use `/verify` to verify your license first')
                    .setFooter({ text: 'TRAUMA License System' });
                
                await interaction.editReply({ embeds: [embed] });
                return;
            }
            
            const result = await apiCall('/api/license/validate', 'POST', { key: verified.key });
            
            const embed = new EmbedBuilder()
                .setColor(result.valid ? 0x00ff88 : 0xff4444)
                .setTitle(result.valid ? '✅ License Active' : '❌ License Invalid')
                .addFields(
                    { name: 'User', value: verified.user, inline: true },
                    { name: 'Days Remaining', value: result.daysRemaining ? `${result.daysRemaining} days` : 'N/A', inline: true },
                    { name: 'Expires', value: new Date(verified.expires).toLocaleDateString(), inline: true }
                )
                .setFooter({ text: 'TRAUMA License System' })
                .setTimestamp();
            
            await interaction.editReply({ embeds: [embed] });
            break;
        }
        
        case 'generate': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const username = options.getString('user');
            const days = options.getInteger('days') || 365;
            
            const result = await apiCall('/api/admin/license/generate', 'POST', { user: username, expiryDays: days });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🔑 License Generated')
                    .addFields(
                        { name: 'User', value: result.license.user, inline: true },
                        { name: 'Key', value: `\`${result.license.key}\``, inline: false },
                        { name: 'Expires', value: new Date(result.license.expiry).toLocaleDateString(), inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
                
                // Try to DM the user who received the key
                try {
                    // Extract Discord ID from username if it's a mention
                    const discordId = username.match(/<@!?(\d+)>/)?.[1] || username;
                    const targetUser = await client.users.fetch(discordId).catch(() => null);
                    
                    if (targetUser) {
                        const dmEmbed = new EmbedBuilder()
                            .setColor(0x00ff88)
                            .setTitle('🎫 Your TRAUMA License Key')
                            .setDescription('You have been issued a TRAUMA license!')
                            .addFields(
                                { name: 'License Key', value: `\`${result.license.key}\``, inline: false },
                                { name: 'Expires', value: new Date(result.license.expiry).toLocaleDateString(), inline: true },
                                { name: 'Days', value: `${days} days`, inline: true },
                                { name: 'How to Use', value: 'Use `/verify` with this key in Discord to activate your license', inline: false }
                            )
                            .setFooter({ text: 'TRAUMA License System - Keep this key safe!' })
                            .setTimestamp();
                        
                        await targetUser.send({ embeds: [dmEmbed] });
                    }
                } catch (e) {
                    // DM failed, but key was generated successfully
                }
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'revoke': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const key = options.getString('key');
            const result = await apiCall('/api/admin/license/revoke', 'POST', { key });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('🚫 License Revoked')
                    .setDescription(`License \`${key}\` has been revoked`)
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'list': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/licenses');
            const limit = options.getInteger('limit') || 10;
            
            if (result.licenses) {
                const licenses = result.licenses.slice(0, limit);
                
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle(`📋 Licenses (${result.licenses.length} total)`)
                    .setDescription(licenses.map((l, i) => 
                        `**${i + 1}.** ${l.user} - \`${l.key.substring(0, 15)}...\` ${l.revoked ? '❌' : '✅'}`
                    ).join('\n'))
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'stats': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/analytics');
            
            if (result.stats) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('📊 License Server Statistics')
                    .addFields(
                        { name: 'Total Events', value: `${result.stats.totalEvents}`, inline: true },
                        { name: 'Validations', value: `${result.stats.validations}`, inline: true },
                        { name: 'Activations', value: `${result.stats.activations}`, inline: true },
                        { name: 'Failed Validations', value: `${result.stats.failedValidations}`, inline: true },
                        { name: 'Licenses Generated', value: `${result.stats.licensesGenerated}`, inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'referral': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                return;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const name = options.getString('name');
            const bonus = options.getInteger('bonus') || 30;
            
            const result = await apiCall('/api/referral/create', 'POST', { name, bonusDays: bonus });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🎁 Referral Code Created')
                    .addFields(
                        { name: 'Code', value: `\`${result.referral.code}\``, inline: true },
                        { name: 'Bonus Days', value: `${bonus} days`, inline: true },
                        { name: 'Max Uses', value: `${result.referral.maxUses}`, inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'extend': {
            await interaction.deferReply({ ephemeral: true });
            
            const code = options.getString('code');
            const key = options.getString('key');
            
            const result = await apiCall('/api/referral/use', 'POST', { referralCode: code, key });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('✅ License Extended')
                    .setDescription(result.message)
                    .addFields(
                        { name: 'New Expiry', value: new Date(result.newExpiry).toLocaleDateString(), inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'help': {
            const embed = new EmbedBuilder()
                .setColor(0xdc143c)
                .setTitle('🛡️ TRAUMA Bot Help')
                .setDescription('License management commands for TRAUMA Suite')
                .addFields(
                    { name: '/verify <key>', value: 'Verify your TRAUMA license' },
                    { name: '/status', value: 'Check your license status' },
                    { name: '/mystats', value: 'Get your license stats via DM' },
                    { name: '/extend <code> <key>', value: 'Extend license with referral code' },
                    { name: '/ticket <subject>', value: 'Create a support ticket' },
                    { name: '/generate <user> [days]', value: 'Generate license (Admin)' },
                    { name: '/revoke <key>', value: 'Revoke license (Admin)' },
                    { name: '/list [limit]', value: 'List licenses (Admin)' },
                    { name: '/stats', value: 'Server statistics (Admin)' },
                    { name: '/referral <name> [bonus]', value: 'Create referral (Admin)' },
                    { name: '/checkreminders', value: 'Check expiring licenses (Admin)' }
                )
                .setFooter({ text: 'One license works for all TRAUMA tools' })
                .setTimestamp();
            
            await interaction.reply({ embeds: [embed], ephemeral: true });
            break;
        }
        
        case 'mystats': {
            await interaction.deferReply({ ephemeral: true });
            
            const verified = verifiedUsers.get(user.id);
            if (!verified) {
                await interaction.editReply({ content: '❌ Use `/verify` first to link your license' });
                break;
            }
            
            const result = await apiCall('/api/license/validate', 'POST', { key: verified.key });
            
            if (result.valid) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('📊 Your License Stats')
                    .addFields(
                        { name: 'User', value: result.user, inline: true },
                        { name: 'Days Remaining', value: `${result.daysRemaining} days`, inline: true },
                        { name: 'Expires', value: new Date(result.expires).toLocaleDateString(), inline: true },
                        { name: 'Features', value: result.features?.join(', ') || 'all', inline: true }
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                // Try to DM the user
                try {
                    const dmChannel = await user.createDM();
                    await dmChannel.send({ embeds: [embed] });
                    await interaction.editReply({ content: '✅ Stats sent to your DMs!' });
                } catch (e) {
                    // Fallback to reply if DM fails
                    await interaction.editReply({ embeds: [embed] });
                }
            } else {
                await interaction.editReply({ content: `❌ ${result.error || 'License invalid'}` });
            }
            break;
        }
        
        case 'ticket': {
            const subject = options.getString('subject');
            
            // Create ticket channel
            const guild = interaction.guild;
            const categoryId = process.env.TICKET_CATEGORY_ID;
            
            try {
                const channel = await guild.channels.create({
                    name: `ticket-${user.username}`,
                    type: 0, // Text channel
                    parent: categoryId || null,
                    permissionOverwrites: [
                        {
                            id: guild.id,
                            deny: ['ViewChannel']
                        },
                        {
                            id: user.id,
                            allow: ['ViewChannel', 'SendMessages', 'ReadMessageHistory']
                        },
                        ...process.env.ADMIN_IDS.split(',').map(adminId => ({
                            id: adminId,
                            allow: ['ViewChannel', 'SendMessages', 'ReadMessageHistory', 'ManageChannels']
                        }))
                    ]
                });
                
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle('🎫 Support Ticket Created')
                    .setDescription(`Ticket created by ${user}`)
                    .addFields(
                        { name: 'Subject', value: subject },
                        { name: 'Instructions', value: 'Describe your issue and an admin will assist you shortly.\nUse `/closeticket` when resolved.' }
                    )
                    .setFooter({ text: 'TRAUMA Support' })
                    .setTimestamp();
                
                await channel.send({ content: `<@${user.id}>`, embeds: [embed] });
                
                await interaction.reply({ 
                    content: `✅ Ticket created: ${channel}`, 
                    ephemeral: true 
                });
            } catch (e) {
                await interaction.reply({ 
                    content: `❌ Failed to create ticket: ${e.message}`, 
                    ephemeral: true 
                });
            }
            break;
        }
        
        case 'checkreminders': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/licenses', 'GET');
            const licenses = result.licenses || [];
            
            const expiring7Days = licenses.filter(l => {
                if (l.revoked) return false;
                const days = Math.ceil((new Date(l.expiry) - new Date()) / (1000 * 60 * 60 * 24));
                return days > 0 && days <= 7;
            });
            
            const expiring30Days = licenses.filter(l => {
                if (l.revoked) return false;
                const days = Math.ceil((new Date(l.expiry) - new Date()) / (1000 * 60 * 60 * 24));
                return days > 7 && days <= 30;
            });
            
            const embed = new EmbedBuilder()
                .setColor(0xffaa00)
                .setTitle('⏰ License Renewal Reminders')
                .addFields(
                    { name: '🔴 Expiring in 7 days', value: expiring7Days.length > 0 ? 
                        expiring7Days.map(l => `${l.user} (${Math.ceil((new Date(l.expiry) - new Date()) / (1000 * 60 * 60 * 24))}d)`).join('\n') : 
                        'None', inline: false },
                    { name: '🟡 Expiring in 30 days', value: expiring30Days.length > 0 ? 
                        expiring30Days.map(l => `${l.user} (${Math.ceil((new Date(l.expiry) - new Date()) / (1000 * 60 * 60 * 24))}d)`).join('\n') : 
                        'None', inline: false }
                )
                .setFooter({ text: 'Send reminders with /sendreminders' })
                .setTimestamp();
            
            await interaction.editReply({ embeds: [embed] });
            break;
        }
        
        case 'sendreminders': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/licenses', 'GET');
            const licenses = result.licenses || [];
            let sent = 0;
            
            for (const license of licenses) {
                if (license.revoked) continue;
                
                const days = Math.ceil((new Date(license.expiry) - new Date()) / (1000 * 60 * 60 * 24));
                
                if (days <= 7 && days > 0) {
                    // Try to find user by stored Discord ID or username
                    try {
                        // Extract Discord ID if stored
                        const discordId = license.user.match(/<@(\d+)>/)?.[1];
                        if (discordId) {
                            const targetUser = await client.users.fetch(discordId);
                            if (targetUser) {
                                const dmEmbed = new EmbedBuilder()
                                    .setColor(0xff4444)
                                    .setTitle('⚠️ License Expiring Soon!')
                                    .setDescription(`Your TRAUMA license expires in **${days} days**!`)
                                    .addFields(
                                        { name: 'Key', value: `\`${license.key.substring(0, 19)}...\`` },
                                        { name: 'Expires', value: new Date(license.expiry).toLocaleDateString() },
                                        { name: 'Renew', value: 'Contact an admin to renew your license' }
                                    )
                                    .setFooter({ text: 'TRAUMA License System' })
                                    .setTimestamp();
                                
                                await targetUser.send({ embeds: [dmEmbed] });
                                sent++;
                            }
                        }
                    } catch (e) {
                        // User not found or DMs disabled
                    }
                }
            }
            
            await interaction.editReply({ content: `✅ Sent ${sent} renewal reminder DMs` });
            break;
        }
        
        case 'createpool': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const name = options.getString('name');
            const count = options.getInteger('count');
            const days = options.getInteger('days') || 365;
            
            const result = await apiCall('/api/admin/pool/create', 'POST', { name, count, expiryDays: days });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('📦 License Pool Created')
                    .addFields(
                        { name: 'Pool Name', value: name, inline: true },
                        { name: 'Pool ID', value: `\`${result.pool.id}\``, inline: true },
                        { name: 'Keys Generated', value: `${count}`, inline: true },
                        { name: 'Duration', value: `${days} days`, inline: true }
                    )
                    .setDescription('Share the Pool ID for users to claim keys with `/claimpool`')
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'listpools': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/pools', 'GET');
            
            if (result.pools && result.pools.length > 0) {
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle('📦 License Pools')
                    .addFields(
                        result.pools.map(p => ({
                            name: p.name,
                            value: `ID: \`${p.id}\`\nClaimed: ${p.claimed}/${p.total}\nRemaining: ${p.remaining}`,
                            inline: true
                        }))
                    )
                    .setFooter({ text: 'TRAUMA License System' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: 'No pools found. Create one with `/createpool`' });
            }
            break;
        }
        
        case 'claimpool': {
            await interaction.deferReply({ ephemeral: true });
            
            const poolId = options.getString('poolid');
            
            const result = await apiCall('/api/pool/claim', 'POST', { poolId, user: `<@${user.id}>` });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🎫 License Claimed!')
                    .addFields(
                        { name: 'License Key', value: `\`${result.license.key}\``, inline: false },
                        { name: 'Expires', value: new Date(result.license.expires).toLocaleDateString(), inline: true },
                        { name: 'Features', value: result.license.features.join(', '), inline: true }
                    )
                    .setDescription('Use `/verify` with this key to activate your license')
                    .setFooter({ text: 'TRAUMA License System - Keep this key safe!' })
                    .setTimestamp();
                
                // DM the user their key
                try {
                    const dmChannel = await user.createDM();
                    await dmChannel.send({ embeds: [embed] });
                    await interaction.editReply({ content: '✅ License key sent to your DMs!' });
                } catch (e) {
                    await interaction.editReply({ embeds: [embed] });
                }
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'auditlog': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const limit = options.getInteger('limit') || 20;
            
            const result = await apiCall(`/api/admin/audit?limit=${limit}`, 'GET');
            
            if (result.logs && result.logs.length > 0) {
                const embed = new EmbedBuilder()
                    .setColor(0x9932cc)
                    .setTitle('📋 Audit Log')
                    .addFields(
                        result.logs.slice(-10).reverse().map(log => ({
                            name: log.action,
                            value: `By: ${log.details.actor}\n${log.details.key ? `Key: \`${log.details.key.substring(0, 19)}...\`` : ''}\n${log.details.user ? `User: ${log.details.user}` : ''}`,
                            inline: false
                        }))
                    )
                    .setFooter({ text: `Showing last 10 of ${result.total} logs` })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: 'No audit logs found' });
            }
            break;
        }
        
        case 'bulkgenerate': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const usersStr = options.getString('users');
            const days = options.getInteger('days') || 365;
            const users = usersStr.split(',').map(u => u.trim()).filter(u => u);
            
            if (users.length > 100) {
                await interaction.editReply({ content: '❌ Maximum 100 users at once' });
                break;
            }
            
            const result = await apiCall('/api/admin/bulk/generate', 'POST', { users, expiryDays: days });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🔑 Bulk Generate Complete')
                    .addFields(
                        { name: 'Generated', value: `${result.generated}`, inline: true },
                        { name: 'Failed', value: `${result.failed}`, inline: true },
                        { name: 'Duration', value: `${days} days`, inline: true }
                    )
                    .setDescription(result.licenses.slice(0, 10).map(l => `**${l.user}**: \`${l.key}\``).join('\n'))
                    .setFooter({ text: result.licenses.length > 10 ? `Showing 10 of ${result.licenses.length}` : '' })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'bulkrevoke': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const keysStr = options.getString('keys');
            const reason = options.getString('reason') || 'Bulk revocation';
            const keys = keysStr.split(',').map(k => k.trim()).filter(k => k);
            
            if (keys.length > 100) {
                await interaction.editReply({ content: '❌ Maximum 100 keys at once' });
                break;
            }
            
            const result = await apiCall('/api/admin/bulk/revoke', 'POST', { keys, reason });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('🚫 Bulk Revoke Complete')
                    .addFields(
                        { name: 'Revoked', value: `${result.revoked}`, inline: true },
                        { name: 'Not Found', value: `${result.notFound}`, inline: true }
                    )
                    .setDescription(`**Reason:** ${reason}`)
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'bulkextend': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const keysStr = options.getString('keys');
            const days = options.getInteger('days');
            const keys = keysStr.split(',').map(k => k.trim()).filter(k => k);
            
            if (keys.length > 100) {
                await interaction.editReply({ content: '❌ Maximum 100 keys at once' });
                break;
            }
            
            const result = await apiCall('/api/admin/bulk/extend', 'POST', { keys, additionalDays: days });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle('⏰ Bulk Extend Complete')
                    .addFields(
                        { name: 'Extended', value: `${result.extended}`, inline: true },
                        { name: 'Days Added', value: `${days}`, inline: true },
                        { name: 'Not Found', value: `${result.notFound}`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'extendexpiring': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const withinDays = options.getInteger('withindays');
            const addDays = options.getInteger('adddays');
            
            const result = await apiCall('/api/admin/bulk/extend-expiring', 'POST', { 
                days: withinDays, 
                additionalDays: addDays 
            });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('⏰ Expiring Licenses Extended')
                    .addFields(
                        { name: 'Extended', value: `${result.extended}`, inline: true },
                        { name: 'Within', value: `${withinDays} days`, inline: true },
                        { name: 'Added', value: `${addDays} days`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'cleanup': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/bulk/cleanup', 'POST');
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🧹 Cleanup Complete')
                    .addFields(
                        { name: 'Removed', value: `${result.removed} revoked licenses`, inline: true },
                        { name: 'Remaining', value: `${result.remaining} active licenses`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: `❌ Error: ${result.error}` });
            }
            break;
        }
        
        case 'adminpanel': {
            if (!isAdmin(user.id)) {
                await interaction.reply({ content: '❌ Admin only command', ephemeral: true });
                break;
            }
            
            const ADMIN_CHANNEL_ID = '1479975115486789775';
            
            try {
                const channel = await client.channels.fetch(ADMIN_CHANNEL_ID);
                if (!channel) {
                    await interaction.reply({ content: '❌ Admin channel not found', ephemeral: true });
                    break;
                }
                
                const panelEmbed = new EmbedBuilder()
                    .setColor(0xdc143c)
                    .setTitle('🛡️ TRAUMA Admin Control Panel')
                    .setDescription('Quick access to admin controls. Click a button below.')
                    .addFields(
                        { name: '🔑 License Management', value: 'Generate, revoke, extend licenses', inline: true },
                        { name: '📦 Pools', value: 'Create and manage license pools', inline: true },
                        { name: '📊 Stats', value: 'View system statistics', inline: true }
                    )
                    .setFooter({ text: 'Admin Only • TRAUMA License System' })
                    .setTimestamp();
                
                const row1 = new ActionRowBuilder()
                    .addComponents(
                        new ButtonBuilder()
                            .setCustomId('admin_generate')
                            .setLabel('Generate License')
                            .setStyle(ButtonStyle.Success)
                            .setEmoji('🔑'),
                        new ButtonBuilder()
                            .setCustomId('admin_revoke')
                            .setLabel('Revoke License')
                            .setStyle(ButtonStyle.Danger)
                            .setEmoji('🚫'),
                        new ButtonBuilder()
                            .setCustomId('admin_extend')
                            .setLabel('Extend License')
                            .setStyle(ButtonStyle.Primary)
                            .setEmoji('⏰')
                    );
                
                const row2 = new ActionRowBuilder()
                    .addComponents(
                        new ButtonBuilder()
                            .setCustomId('admin_pool')
                            .setLabel('Create Pool')
                            .setStyle(ButtonStyle.Success)
                            .setEmoji('📦'),
                        new ButtonBuilder()
                            .setCustomId('admin_stats')
                            .setLabel('View Stats')
                            .setStyle(ButtonStyle.Primary)
                            .setEmoji('📊'),
                        new ButtonBuilder()
                            .setCustomId('admin_list')
                            .setLabel('List Licenses')
                            .setStyle(ButtonStyle.Secondary)
                            .setEmoji('📋')
                    );
                
                const row3 = new ActionRowBuilder()
                    .addComponents(
                        new ButtonBuilder()
                            .setCustomId('admin_bulkgen')
                            .setLabel('Bulk Generate')
                            .setStyle(ButtonStyle.Success)
                            .setEmoji('⚡'),
                        new ButtonBuilder()
                            .setCustomId('admin_extendexpiring')
                            .setLabel('Extend Expiring')
                            .setStyle(ButtonStyle.Primary)
                            .setEmoji('⏳'),
                        new ButtonBuilder()
                            .setCustomId('admin_cleanup')
                            .setLabel('Cleanup Revoked')
                            .setStyle(ButtonStyle.Danger)
                            .setEmoji('🧹')
                    );
                
                await channel.send({ 
                    embeds: [panelEmbed], 
                    components: [row1, row2, row3] 
                });
                
                await interaction.reply({ content: '✅ Admin panel sent to channel', ephemeral: true });
            } catch (e) {
                await interaction.reply({ content: `❌ Error: ${e.message}`, ephemeral: true });
            }
            break;
        }
    }
});

// Handle button interactions for admin panel
client.on('interactionCreate', async interaction => {
    if (!interaction.isButton()) return;
    
    const { customId, user } = interaction;
    
    // All admin panel buttons require admin check
    if (customId.startsWith('admin_') && !isAdmin(user.id)) {
        await interaction.reply({ content: '❌ Admin only', ephemeral: true });
        return;
    }
    
    switch (customId) {
        case 'admin_generate': {
            const modal = new ModalBuilder()
                .setCustomId('modal_generate')
                .setTitle('Generate License');
            
            const user_input = new TextInputBuilder()
                .setCustomId('gen_user')
                .setLabel('User (Discord ID or name)')
                .setStyle(TextInputStyle.Short)
                .setRequired(true);
            
            const days_input = new TextInputBuilder()
                .setCustomId('gen_days')
                .setLabel('Duration (days)')
                .setStyle(TextInputStyle.Short)
                .setValue('365')
                .setRequired(true);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(user_input),
                new ActionRowBuilder().addComponents(days_input)
            );
            
            await interaction.showModal(modal);
            break;
        }
        
        case 'admin_revoke': {
            const modal = new ModalBuilder()
                .setCustomId('modal_revoke')
                .setTitle('Revoke License');
            
            const key_input = new TextInputBuilder()
                .setCustomId('revoke_key')
                .setLabel('License Key')
                .setStyle(TextInputStyle.Short)
                .setRequired(true);
            
            const reason_input = new TextInputBuilder()
                .setCustomId('revoke_reason')
                .setLabel('Reason')
                .setStyle(TextInputStyle.Short)
                .setRequired(false);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(key_input),
                new ActionRowBuilder().addComponents(reason_input)
            );
            
            await interaction.showModal(modal);
            break;
        }
        
        case 'admin_extend': {
            const modal = new ModalBuilder()
                .setCustomId('modal_extend')
                .setTitle('Extend License');
            
            const key_input = new TextInputBuilder()
                .setCustomId('extend_key')
                .setLabel('License Key')
                .setStyle(TextInputStyle.Short)
                .setRequired(true);
            
            const days_input = new TextInputBuilder()
                .setCustomId('extend_days')
                .setLabel('Days to Add')
                .setStyle(TextInputStyle.Short)
                .setValue('30')
                .setRequired(true);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(key_input),
                new ActionRowBuilder().addComponents(days_input)
            );
            
            await interaction.showModal(modal);
            break;
        }
        
        case 'admin_pool': {
            const modal = new ModalBuilder()
                .setCustomId('modal_pool')
                .setTitle('Create License Pool');
            
            const name_input = new TextInputBuilder()
                .setCustomId('pool_name')
                .setLabel('Pool Name')
                .setStyle(TextInputStyle.Short)
                .setRequired(true);
            
            const count_input = new TextInputBuilder()
                .setCustomId('pool_count')
                .setLabel('Number of Keys (1-100)')
                .setStyle(TextInputStyle.Short)
                .setValue('10')
                .setRequired(true);
            
            const days_input = new TextInputBuilder()
                .setCustomId('pool_days')
                .setLabel('Duration (days)')
                .setStyle(TextInputStyle.Short)
                .setValue('365')
                .setRequired(true);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(name_input),
                new ActionRowBuilder().addComponents(count_input),
                new ActionRowBuilder().addComponents(days_input)
            );
            
            await interaction.showModal(modal);
            break;
        }
        
        case 'admin_stats': {
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/licenses');
            
            if (result.licenses) {
                const active = result.licenses.filter(l => !l.revoked).length;
                const expired = result.licenses.filter(l => !l.revoked && new Date(l.expiry) < new Date()).length;
                
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle('📊 License Statistics')
                    .addFields(
                        { name: 'Total', value: `${result.licenses.length}`, inline: true },
                        { name: 'Active', value: `${active}`, inline: true },
                        { name: 'Expired', value: `${expired}`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: '❌ Failed to load stats' });
            }
            break;
        }
        
        case 'admin_list': {
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/licenses');
            
            if (result.licenses) {
                const list = result.licenses.slice(0, 10).map(l => 
                    `**${l.user}**: \`${l.key.substring(0, 19)}...\` ${l.revoked ? '❌' : '✅'}`
                ).join('\n');
                
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle('📋 Recent Licenses')
                    .setDescription(list || 'No licenses')
                    .setFooter({ text: `Showing 10 of ${result.licenses.length}` })
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: '❌ Failed to load licenses' });
            }
            break;
        }
        
        case 'admin_bulkgen': {
            const modal = new ModalBuilder()
                .setCustomId('modal_bulkgen')
                .setTitle('Bulk Generate Licenses');
            
            const users_input = new TextInputBuilder()
                .setCustomId('bulk_users')
                .setLabel('Users (comma-separated)')
                .setStyle(TextInputStyle.Paragraph)
                .setRequired(true);
            
            const days_input = new TextInputBuilder()
                .setCustomId('bulk_days')
                .setLabel('Duration (days)')
                .setStyle(TextInputStyle.Short)
                .setValue('365')
                .setRequired(true);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(users_input),
                new ActionRowBuilder().addComponents(days_input)
            );
            
            await interaction.showModal(modal);
            break;
        }
        
        case 'admin_extendexpiring': {
            const modal = new ModalBuilder()
                .setCustomId('modal_extendexpiring')
                .setTitle('Extend Expiring Licenses');
            
            const within_input = new TextInputBuilder()
                .setCustomId('expiring_within')
                .setLabel('Expiring within (days)')
                .setStyle(TextInputStyle.Short)
                .setValue('7')
                .setRequired(true);
            
            const add_input = new TextInputBuilder()
                .setCustomId('expiring_add')
                .setLabel('Days to add')
                .setStyle(TextInputStyle.Short)
                .setValue('30')
                .setRequired(true);
            
            modal.addComponents(
                new ActionRowBuilder().addComponents(within_input),
                new ActionRowBuilder().addComponents(add_input)
            );
            
            await interaction.showModal(modal);
            break;
        }
        
        case 'admin_cleanup': {
            await interaction.deferReply({ ephemeral: true });
            
            const result = await apiCall('/api/admin/bulk/cleanup', 'POST');
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🧹 Cleanup Complete')
                    .addFields(
                        { name: 'Removed', value: `${result.removed} revoked licenses`, inline: true },
                        { name: 'Remaining', value: `${result.remaining} active licenses`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.editReply({ embeds: [embed] });
            } else {
                await interaction.editReply({ content: '❌ Cleanup failed' });
            }
            break;
        }
    }
});

// Handle modal submissions
client.on('interactionCreate', async interaction => {
    if (!interaction.isModalSubmit()) return;
    
    const { customId, user } = interaction;
    
    // All admin modals require admin check
    if (customId.startsWith('modal_') && !isAdmin(user.id)) {
        await interaction.reply({ content: '❌ Admin only', ephemeral: true });
        return;
    }
    
    switch (customId) {
        case 'modal_generate': {
            const targetUser = interaction.fields.getTextInputValue('gen_user');
            const days = parseInt(interaction.fields.getTextInputValue('gen_days'));
            
            const result = await apiCall('/api/admin/license/generate', 'POST', { 
                user: targetUser, 
                expiryDays: days 
            });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🔑 License Generated')
                    .addFields(
                        { name: 'User', value: targetUser, inline: true },
                        { name: 'Key', value: `\`${result.license.key}\``, inline: false },
                        { name: 'Expires', value: new Date(result.license.expiry).toLocaleDateString(), inline: true }
                    )
                    .setTimestamp();
                
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                await interaction.reply({ content: `❌ Error: ${result.error}`, ephemeral: true });
            }
            break;
        }
        
        case 'modal_revoke': {
            const key = interaction.fields.getTextInputValue('revoke_key');
            const reason = interaction.fields.getTextInputValue('revoke_reason') || 'No reason provided';
            
            const result = await apiCall('/api/admin/license/revoke', 'POST', { key, reason });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0xff4444)
                    .setTitle('🚫 License Revoked')
                    .addFields(
                        { name: 'Key', value: `\`${key.substring(0, 19)}...\``, inline: true },
                        { name: 'Reason', value: reason, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                await interaction.reply({ content: `❌ Error: ${result.error}`, ephemeral: true });
            }
            break;
        }
        
        case 'modal_extend': {
            const key = interaction.fields.getTextInputValue('extend_key');
            const days = parseInt(interaction.fields.getTextInputValue('extend_days'));
            
            const result = await apiCall('/api/admin/license/extend', 'POST', { key, additionalDays: days });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x0088ff)
                    .setTitle('⏰ License Extended')
                    .addFields(
                        { name: 'Key', value: `\`${key.substring(0, 19)}...\``, inline: true },
                        { name: 'Days Added', value: `${days}`, inline: true },
                        { name: 'New Expiry', value: new Date(result.license.expiry).toLocaleDateString(), inline: true }
                    )
                    .setTimestamp();
                
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                await interaction.reply({ content: `❌ Error: ${result.error}`, ephemeral: true });
            }
            break;
        }
        
        case 'modal_pool': {
            const name = interaction.fields.getTextInputValue('pool_name');
            const count = parseInt(interaction.fields.getTextInputValue('pool_count'));
            const days = parseInt(interaction.fields.getTextInputValue('pool_days'));
            
            const result = await apiCall('/api/admin/pool/create', 'POST', { 
                name, 
                count, 
                expiryDays: days 
            });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('📦 Pool Created')
                    .addFields(
                        { name: 'Name', value: name, inline: true },
                        { name: 'Pool ID', value: `\`${result.pool.id}\``, inline: true },
                        { name: 'Keys', value: `${count}`, inline: true }
                    )
                    .setDescription(`Users can claim with \`/claimpool ${result.pool.id}\``)
                    .setTimestamp();
                
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                await interaction.reply({ content: `❌ Error: ${result.error}`, ephemeral: true });
            }
            break;
        }
        
        case 'modal_bulkgen': {
            const usersStr = interaction.fields.getTextInputValue('bulk_users');
            const days = parseInt(interaction.fields.getTextInputValue('bulk_days'));
            const users = usersStr.split(',').map(u => u.trim()).filter(u => u);
            
            const result = await apiCall('/api/admin/bulk/generate', 'POST', { 
                users, 
                expiryDays: days 
            });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('🔑 Bulk Generate Complete')
                    .addFields(
                        { name: 'Generated', value: `${result.generated}`, inline: true },
                        { name: 'Failed', value: `${result.failed}`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                await interaction.reply({ content: `❌ Error: ${result.error}`, ephemeral: true });
            }
            break;
        }
        
        case 'modal_extendexpiring': {
            const withinDays = parseInt(interaction.fields.getTextInputValue('expiring_within'));
            const addDays = parseInt(interaction.fields.getTextInputValue('expiring_add'));
            
            const result = await apiCall('/api/admin/bulk/extend-expiring', 'POST', { 
                days: withinDays, 
                additionalDays: addDays 
            });
            
            if (result.success) {
                const embed = new EmbedBuilder()
                    .setColor(0x00ff88)
                    .setTitle('⏰ Expiring Licenses Extended')
                    .addFields(
                        { name: 'Extended', value: `${result.extended}`, inline: true },
                        { name: 'Days Added', value: `${addDays}`, inline: true }
                    )
                    .setTimestamp();
                
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                await interaction.reply({ content: `❌ Error: ${result.error}`, ephemeral: true });
            }
            break;
        }
    }
});

// Login
client.login(DISCORD_TOKEN);

module.exports = client;
